package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/coder/websocket"
)

const (
	DefaultWSPath = "/ws"
	wsScheme      = "wss"
)

// WSTLSOptions configures the ws-tls transport.
type WSTLSOptions struct {
	ServerAddr  string // host[:port]; port 443 added if missing
	ServerName  string // optional SNI override; defaults to host part of ServerAddr
	WSPath      string // defaults to DefaultWSPath
	Fingerprint string // hex SHA-256 pin of the server certificate
	Insecure    bool   // dev only: skip pin verification
	DialTimeout time.Duration
	ChromeHello bool // mimic Chrome's TLS ClientHello (uTLS)
}

type wsTLSTransport struct{ opt WSTLSOptions }

func NewWSTLS(opt WSTLSOptions) Transport { return &wsTLSTransport{opt: opt} }

func (t *wsTLSTransport) Name() string { return "ws-tls" }

func (o *WSTLSOptions) wsPathOrDefault() string {
	if o.WSPath == "" {
		return DefaultWSPath
	}
	return o.WSPath
}

func (t *wsTLSTransport) tlsConfig(host string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we pin instead of using system roots
		MinVersion:         tls.VersionTLS12,
	}
	if t.opt.ServerName != "" {
		cfg.ServerName = t.opt.ServerName
	}
	if !t.opt.Insecure {
		pin, err := ParseFingerprint(t.opt.Fingerprint)
		if err != nil {
			return nil, err
		}
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPin(pin, rawCerts)
		}
	}
	return cfg, nil
}

func verifyPin(pin []byte, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("transport: no certificates presented")
	}
	got := FingerprintCert(rawCerts[0])
	for i := range pin {
		if pin[i] != got[i] {
			return errors.New("transport: server certificate fingerprint mismatch")
		}
	}
	return nil
}

func (t *wsTLSTransport) Dial(ctx context.Context) (net.Conn, error) {
	hostPort := t.opt.ServerAddr
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		hostPort = net.JoinHostPort(hostPort, "443")
	}
	host, _, _ := net.SplitHostPort(hostPort)

	tlsCfg, err := t.tlsConfig(host)
	if err != nil {
		return nil, err
	}
	timeout := t.opt.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := fmt.Sprintf("%s://%s%s", wsScheme, hostPort, t.opt.wsPathOrDefault())
	httpClient := newPinnedHTTPClient(tlsCfg, timeout, t.opt.ChromeHello)

	conn, _, err := websocket.Dial(dctx, url, &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{"otu1"},
	})
	if err != nil {
		return nil, fmt.Errorf("transport: websocket dial %s: %w", url, err)
	}
	// Note: the 101 response's body is managed by the websocket library.
	stream := websocket.NetConn(ctx, conn, websocket.MessageBinary)
	return &wsConn{
		Conn: stream,
		wsc:  conn,
		close: func() {
			_ = conn.Close(websocket.StatusNormalClosure, "")
		},
	}, nil
}

// wsConn couples the stream with explicit websocket teardown.
type wsConn struct {
	net.Conn
	wsc   *websocket.Conn
	close func()
}

func (c *wsConn) Close() error {
	err := c.Conn.Close()
	c.close()
	return err
}

// newPinnedHTTPClient returns an http.Client whose TLS dial uses cfg,
// bypassing system roots so fingerprint pinning governs trust. When chrome is
// true the ClientHello mimics Chrome via uTLS (balanced/stealth profiles).
func newPinnedHTTPClient(cfg *tls.Config, timeout time.Duration, chrome bool) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				if !chrome {
					tconn := tls.Client(raw, cfg)
					if err := tconn.HandshakeContext(ctx); err != nil {
						_ = raw.Close()
						return nil, err
					}
					return tconn, nil
				}
				// Chrome's fingerprint ships ALPN h2+http/1.1, but our
				// transport speaks HTTP/1.1 WebSocket upgrades — rewrite the
				// spec's ALPN to match while keeping every other byte of the
				// Chrome hello intact.
				spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
				if err != nil {
					_ = raw.Close()
					return nil, fmt.Errorf("transport: chrome spec: %w", err)
				}
				for _, ext := range spec.Extensions {
					if alpn, ok := ext.(*utls.ALPNExtension); ok {
						alpn.AlpnProtocols = []string{"http/1.1"}
						break
					}
				}
				ucfg := &utls.Config{
					ServerName: cfg.ServerName,
					// Pins govern trust; skip system roots exactly as in the
					// non-uTLS path above.
					InsecureSkipVerify:    true,
					MinVersion:            tls.VersionTLS12,
					VerifyPeerCertificate: cfg.VerifyPeerCertificate,
				}
				uconn := utls.UClient(raw, ucfg, utls.HelloCustom)
				if err := uconn.ApplyPreset(&spec); err != nil {
					_ = raw.Close()
					return nil, fmt.Errorf("transport: apply chrome spec: %w", err)
				}
				if err := uconn.HandshakeContext(ctx); err != nil {
					_ = raw.Close()
					return nil, err
				}
				if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
					_ = raw.Close()
					return nil, fmt.Errorf("transport: unexpected ALPN %q under Chrome hello", proto)
				}
				return uconn, nil
			},
			ForceAttemptHTTP2: false,
		},
		Timeout: timeout,
	}
}
