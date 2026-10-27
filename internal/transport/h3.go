// h3.go: the HTTP/3 transport tier. QUIC to :443 cannot be transparently
// intercepted by TLS-inspecting middleboxes (they cannot re-sign what they
// cannot terminate), so the pinned handshake inside it reaches the relay
// untouched — the tier that keeps bulk traffic moving on networks where
// every TCP/TLS flow is resigned. The tunnel protocol rides a streaming
// fetch-style POST (no WebSocket upgrade exists over h3 in our stack);
// the byte pipe is wrapped as a net.Conn, so the handshake, AEAD framing,
// mux and control channel above it are unchanged.
//
// Fingerprint note: quic-go's QUIC initial is not Chrome-shaped (uTLS has
// no uquic release yet). Middleboxes that merely cannot parse QUIC —
// the common enterprise case — are defeated regardless; deep QUIC hello
// classifiers are future work pending a parrotable hello.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// H3Options configures the HTTP/3 transport. The pin/entry fields mirror
// WSTLSOptions so the same rotation pin sets apply.
type H3Options struct {
	ServerAddr   string   // host[:port]; port 443 added if missing
	ServerName   string   // optional SNI override; defaults to host part
	Path         string   // tunnel endpoint; defaults to DefaultWSPath
	Fingerprint  string   // hex SHA-256 pin of the server certificate
	Fingerprints []string // rotation set (learned pins rejoin here)
	Insecure     bool     // dev only: skip pin verification
	DialTimeout  time.Duration
}

type h3Transport struct {
	opt H3Options
}

// NewH3 builds the HTTP/3 transport tier.
func NewH3(opt H3Options) Transport { return &h3Transport{opt: opt} }

func (t *h3Transport) Name() string { return "h3" }

func (o *H3Options) pathOrDefault() string {
	if o.Path == "" {
		return DefaultWSPath
	}
	return o.Path
}

func (t *h3Transport) tlsConfig(host string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: host,
		// Pins govern trust, exactly as in ws-tls: system roots are not
		// consulted, and a middlebox certificate fails the pin even though
		// the middlebox cannot actually reach inside QUIC to present one.
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
	}
	if t.opt.ServerName != "" {
		cfg.ServerName = t.opt.ServerName
	}
	if !t.opt.Insecure {
		pins, err := buildPinSet(t.opt.Fingerprint, t.opt.Fingerprints)
		if err != nil {
			return nil, err
		}
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return VerifyPinSet(pins, rawCerts)
		}
	}
	return cfg, nil
}

// Dial opens one HTTP/3 request whose streaming bodies form the byte
// pipe for the tunnel protocol.
func (t *h3Transport) Dial(ctx context.Context) (net.Conn, error) {
	hostPort := t.opt.ServerAddr
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		hostPort = net.JoinHostPort(hostPort, "443")
	}
	host, _, _ := net.SplitHostPort(hostPort)
	sni := host
	if t.opt.ServerName != "" {
		sni = t.opt.ServerName
	}

	tlsCfg, err := t.tlsConfig(host)
	if err != nil {
		return nil, err
	}

	timeout := t.opt.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// The request stream must outlive this function: the protocol
	// handshake only flows after Dial returns. Dial-scoped contexts
	// cancel the stream on return (H3_REQUEST_CANCELLED), so the request
	// carries a conn-owned context and the timeout races the round trip
	// from outside.
	rctx, rcancel := context.WithCancel(ctx)
	owned := false // the conn takes exclusive ownership of rcancel on success
	defer func() {
		if !owned {
			rcancel()
		}
	}()

	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      quicDialConfig(),
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost,
		"https://"+hostPort+t.opt.pathOrDefault(), pr)
	if err != nil {
		return nil, err
	}
	// The browser story for h3: a same-origin streaming fetch() from the
	// site's own page (browsers do exactly this for realtime uploads).
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("sec-ch-ua", `"Not(A:Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("Origin", "https://"+sni)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	type rtResult struct {
		resp *http.Response
		err  error
	}
	ch := make(chan rtResult, 1)
	go func() {
		resp, rerr := tr.RoundTrip(req)
		ch <- rtResult{resp, rerr}
	}()
	var resp *http.Response
	select {
	case r := <-ch:
		resp, err = r.resp, r.err
	case <-time.After(timeout):
		rcancel()
		_ = tr.Close()
		return nil, fmt.Errorf("transport: h3 dial %s: timeout", hostPort)
	}
	if err != nil {
		_ = tr.Close()
		_ = pw.CloseWithError(err)
		return nil, fmt.Errorf("transport: h3 dial %s: %w", hostPort, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		_ = tr.Close()
		_ = pw.CloseWithError(errors.New("transport: h3 status " + resp.Status))
		return nil, fmt.Errorf("transport: h3 dial %s: status %s", hostPort, resp.Status)
	}
	owned = true
	return &h3ClientConn{
		pw:     pw,
		body:   resp.Body,
		tr:     tr,
		cancel: rcancel,
	}, nil
}

// h3ClientConn adapts the request/response body pair into a net.Conn for
// the protocol layers above.
type h3ClientConn struct {
	pw     *io.PipeWriter
	body   io.ReadCloser
	tr     *http3.Transport
	cancel context.CancelFunc
}

func (c *h3ClientConn) Read(p []byte) (int, error) { return c.body.Read(p) }
func (c *h3ClientConn) Write(p []byte) (int, error) {
	n, err := c.pw.Write(p)
	if err != nil {
		return n, err
	}
	return n, nil
}
func (c *h3ClientConn) Close() error {
	_ = c.pw.CloseWithError(errors.New("transport: closed"))
	_ = c.body.Close()
	// The transport owns the pooled QUIC connection; closing it tears
	// down the conn this stream rides. Sessions close the conn when
	// they rotate, so the lifecycle travels with the tunnel session.
	_ = c.tr.Close()
	c.cancel()
	return nil
}
func (c *h3ClientConn) LocalAddr() net.Addr                { return dummyH3Addr{} }
func (c *h3ClientConn) RemoteAddr() net.Addr               { return dummyH3Addr{} }
func (c *h3ClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *h3ClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h3ClientConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyH3Addr struct{}

func (dummyH3Addr) Network() string { return "udp" }
func (dummyH3Addr) String() string  { return "h3" }

// quicDialConfig keeps QUIC connections alive across NAT idle windows
// (smux keepalives plus QUIC's own keepalive below the MaxIdleTimeout)
// while failing fast enough that a UDP-blocked network falls through to
// the next tier without a long stall.
func quicDialConfig() *quic.Config {
	cfg := &quic.Config{
		KeepAlivePeriod:      15 * time.Second,
		MaxIdleTimeout:       90 * time.Second,
		HandshakeIdleTimeout: 8 * time.Second,
	}
	return cfg
}
