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
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"opentunnel/internal/protocol"
)

// H3Options configures the HTTP/3 transport. The pin/entry fields mirror
// WSTLSOptions so the same rotation pin sets apply.
type H3Options struct {
	ServerAddr    string   // host[:port]; port 443 added if missing
	ServerName    string   // optional SNI override; defaults to host part
	HTTPAuthority string   // trusted HTTP host:port independent of TCP/UDP override
	Path          string   // tunnel endpoint; defaults to DefaultWSPath
	Fingerprint   string   // hex SHA-256 pin of the server certificate
	Fingerprints  []string // rotation set (learned pins rejoin here)
	Insecure      bool     // dev only: skip pin verification
	DialTimeout   time.Duration
}

type h3Transport struct {
	opt H3Options

	// One shared http3.Transport per tier (audit rounds three/four): every
	// Dial used to mint a fresh QUIC connection and a fresh handshake per
	// mux rotation — slower and a "browser reconnecting on a metronome"
	// flow-shape tell. The transport pools the QUIC connection across
	// sessions; streams still close independently.
	trOnce        sync.Once
	tr            *http3.Transport
	trErr         error
	udp           *net.UDPConn
	quicTransport *quic.Transport
	closeOnce     sync.Once
	closeErr      error
	ctx           context.Context
	cancel        context.CancelFunc
}

// sharedTransport lazily builds (once) the pooled HTTP/3 transport.
func (t *h3Transport) sharedTransport(tlsCfg *tls.Config) (*http3.Transport, error) {
	t.trOnce.Do(func() {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			t.trErr = err
			return
		}
		t.udp = conn
		t.quicTransport = &quic.Transport{Conn: conn}
		t.tr = &http3.Transport{
			TLSClientConfig: tlsCfg,
			QUICConfig:      quicDialConfig(),
			Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				stop := context.AfterFunc(t.ctx, cancel)
				defer stop()
				addr := t.opt.ServerAddr
				if _, _, err := net.SplitHostPort(addr); err != nil {
					addr = net.JoinHostPort(addr, "443")
				}
				target, err := resolveH3Address(ctx, addr)
				if err != nil {
					return nil, err
				}
				return t.quicTransport.DialEarly(ctx, target, cfg, qcfg)
			},
		}
	})
	return t.tr, t.trErr
}

// NewH3 builds the HTTP/3 transport tier.
func NewH3(opt H3Options) Transport {
	ctx, cancel := context.WithCancel(context.Background())
	return &h3Transport{opt: opt, ctx: ctx, cancel: cancel}
}

func resolveH3Address(ctx context.Context, address string) (*net.UDPAddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("transport: invalid QUIC port")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("transport: QUIC hostname has no address")
	}
	return &net.UDPAddr{IP: addresses[0].IP, Zone: addresses[0].Zone, Port: port}, nil
}

func (t *h3Transport) Name() string { return "h3" }

func (t *h3Transport) Close() error {
	t.closeOnce.Do(func() {
		if t.cancel != nil {
			t.cancel()
		} // cancel DNS before Transport.Close waits for its dial job
		t.trOnce.Do(func() { t.trErr = net.ErrClosed })
		if t.tr != nil {
			t.closeErr = t.tr.Close()
		}
		if t.quicTransport != nil {
			t.closeErr = errors.Join(t.closeErr, t.quicTransport.Close())
		}
		if t.udp != nil {
			t.closeErr = errors.Join(t.closeErr, t.udp.Close())
		}
	})
	return t.closeErr
}

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
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			return verifyConnectionPins(pins, cs.PeerCertificates)
		}
	}
	return cfg, nil
}

// Dial opens one HTTP/3 request whose streaming bodies form the byte
// pipe for the tunnel protocol.
func (t *h3Transport) Dial(ctx context.Context) (net.Conn, error) {
	return t.DialSetup(ctx, ctx)
}

func (t *h3Transport) DialSetup(setup, lifetime context.Context) (net.Conn, error) {
	hostPort := t.opt.ServerAddr
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		hostPort = net.JoinHostPort(hostPort, "443")
	}
	host, port, _ := net.SplitHostPort(hostPort)
	authority := hostPort
	if t.opt.ServerName != "" {
		authority = net.JoinHostPort(t.opt.ServerName, port)
	}
	if t.opt.HTTPAuthority != "" {
		authority = t.opt.HTTPAuthority
	}

	tlsCfg, err := t.tlsConfig(host)
	if err != nil {
		return nil, err
	}

	timeout := t.opt.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dctx, cancelSetup := context.WithTimeout(setup, timeout)
	defer cancelSetup()
	// The request stream must outlive this function: the protocol
	// handshake only flows after Dial returns. Dial-scoped contexts
	// cancel the stream on return (H3_REQUEST_CANCELLED), so the request
	// carries a conn-owned context and the timeout races the round trip
	// from outside.
	rctx, rcancel := context.WithCancel(lifetime)
	stopSetup := context.AfterFunc(dctx, rcancel)
	defer stopSetup()
	owned := false // the conn takes exclusive ownership of rcancel on success
	defer func() {
		if !owned {
			rcancel()
		}
	}()

	tr, terr := t.sharedTransport(tlsCfg)
	if terr != nil {
		rcancel()
		return nil, fmt.Errorf("transport: h3 transport: %w", terr)
	}

	pr, pw := io.Pipe()
	defer func() {
		if !owned {
			_ = pr.Close()
			_ = pw.Close()
		}
	}()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost,
		"https://"+authority+t.opt.pathOrDefault(), pr)
	if err != nil {
		return nil, err
	}
	// The browser story for h3: a same-origin streaming fetch() from the
	// site's own page (browsers do exactly this for realtime uploads).
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(protocol.StreamingHeader, protocol.StreamingValue)
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("sec-ch-ua", `"Not(A:Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("Origin", "https://"+authority)
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
		if rctx.Err() != nil && resp != nil {
			_ = resp.Body.Close()
			resp = nil
			rerr = rctx.Err()
		}
		ch <- rtResult{resp, rerr}
	}()
	var resp *http.Response
	select {
	case r := <-ch:
		resp, err = r.resp, r.err
	case <-dctx.Done():
		rcancel()
		return nil, dctx.Err()
	}
	if err != nil {
		_ = pw.CloseWithError(err)
		return nil, fmt.Errorf("transport: h3 dial %s: %w", hostPort, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		_ = pw.CloseWithError(errors.New("transport: h3 status " + resp.Status))
		return nil, fmt.Errorf("transport: h3 dial %s: status %s", hostPort, resp.Status)
	}
	if !stopSetup() || dctx.Err() != nil {
		rcancel()
		_ = resp.Body.Close()
		if err := dctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}
	owned = true
	return &h3ClientConn{
		pw:     pw,
		body:   resp.Body,
		cancel: rcancel,
	}, nil
}

// h3ClientConn adapts the request/response body pair into a net.Conn for
// the protocol layers above. The shared http3.Transport outlives it: Close
// ends this session's stream only, leaving the pooled QUIC connection for
// the next dial.
type h3ClientConn struct {
	pw     *io.PipeWriter
	body   io.ReadCloser
	cancel context.CancelFunc

	dlMu       sync.Mutex
	readTimer  *time.Timer
	writeTimer *time.Timer
	readEpoch  uint64
	writeEpoch uint64
	closed     bool
	closeOnce  sync.Once
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
	c.closeOnce.Do(func() {
		c.dlMu.Lock()
		c.closed = true
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.dlMu.Unlock()
		_ = c.pw.CloseWithError(errors.New("transport: closed"))
		_ = c.body.Close()
		// Only this stream dies: the shared transport keeps the pooled QUIC
		// connection for the next mux session (connection reuse is both
		// faster and a more browser-like flow shape).
		c.cancel()
	})
	return nil
}
func (c *h3ClientConn) CloseNow() error      { return c.Close() }
func (c *h3ClientConn) CloseWrite() error    { return c.pw.Close() }
func (c *h3ClientConn) LocalAddr() net.Addr  { return dummyH3Addr{} }
func (c *h3ClientConn) RemoteAddr() net.Addr { return dummyH3Addr{} }

// SetDeadline arms an absolute deadline that FORCE-CLOSES the stream on
// expiry (audit round three, N-4: the no-op shim let a stalled handshake
// hold the mux dial forever). The mux session factory clears the deadline
// once the session is authenticated, so this only ever bounds setup.
func (c *h3ClientConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *h3ClientConn) setDirectionDeadline(deadline time.Time, read bool) error {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	timer, epoch := &c.writeTimer, &c.writeEpoch
	if read {
		timer, epoch = &c.readTimer, &c.readEpoch
	}
	*epoch++
	generation := *epoch
	if *timer != nil {
		(*timer).Stop()
		*timer = nil
	}
	if deadline.IsZero() {
		return nil
	}
	*timer = time.AfterFunc(max(0, time.Until(deadline)), func() {
		c.dlMu.Lock()
		current := c.writeEpoch
		if read {
			current = c.readEpoch
		}
		active := !c.closed && current == generation
		if active {
			c.closed = true
		} // timer wins atomically against a later deadline clear
		c.dlMu.Unlock()
		if active {
			_ = c.Close()
		}
	})
	return nil
}

func (c *h3ClientConn) SetReadDeadline(t time.Time) error  { return c.setDirectionDeadline(t, true) }
func (c *h3ClientConn) SetWriteDeadline(t time.Time) error { return c.setDirectionDeadline(t, false) }

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
