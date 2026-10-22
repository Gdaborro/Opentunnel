package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/coder/websocket"

	"opentunnel/internal/protocol"
)

const (
	// DefaultWSPath mirrors protocol.DefaultWSPath (kept for compatibility).
	DefaultWSPath = protocol.DefaultWSPath
	wsScheme      = "wss"
)

// browserUA imitates a current Chrome on the plaintext upgrade request: the
// stock Go client would otherwise announce "Go-http-client" and offer a
// custom subprotocol — both machine-identifiable under interception.
// Version pinned to the uTLS parrot (HelloChrome_Auto == Chrome 133):
// handshake and headers must tell the SAME version story. Recheck when
// bumping github.com/refraction-networking/utls.
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// BrowserUA is the shared view of browserUA: every HTTPS request this binary
// makes — tunnel, control plane and updates alike — tells the same
// Chrome-version story (see pinnedhttp.go).
const BrowserUA = browserUA

// WSTLSOptions configures the ws-tls transport.
type WSTLSOptions struct {
	ServerAddr  string // host[:port]; port 443 added if missing
	ServerName  string // optional SNI override; defaults to host part of ServerAddr
	WSPath      string // defaults to DefaultWSPath
	Fingerprint string // hex SHA-256 pin of the server certificate
	// Fingerprints are additional accepted pins (rotation): the leaf
	// changes at every Let's Encrypt renewal, and pins learned in-band
	// from the relay rejoin here. Any listed pin verifies.
	Fingerprints []string
	Insecure     bool          // dev only: skip pin verification
	DialTimeout  time.Duration // per-transport dial budget
	ChromeHello  bool          // mimic Chrome's TLS ClientHello (uTLS)
}

type wsTLSTransport struct{ opt WSTLSOptions }

func NewWSTLS(opt WSTLSOptions) Transport { return &wsTLSTransport{opt: opt} }

// sessionCache is shared by every dial in the process: resumed handshakes
// are shorter, faster, and far less distinctive than full handshakes — which
// matters most exactly when sessions churn (rotation windows, TTL quotas).
// The cache holds tickets, never credentials; entries are keyed by endpoint.
var sessionCache = tls.NewLRUClientSessionCache(64)

// utlsCache is the same idea for Chrome-hello dials (uTLS has its own
// session-state type, so the stdlib cache cannot be shared).
var utlsCache = newUTLSSessionCache()

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
		ClientSessionCache: sessionCache,
	}
	if t.opt.ServerName != "" {
		cfg.ServerName = t.opt.ServerName
	}
	if !t.opt.Insecure {
		pins, err := t.opt.pinSet()
		if err != nil {
			return nil, err
		}
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return VerifyPinSet(pins, rawCerts)
		}
	}
	return cfg, nil
}

// pinSet parses every configured fingerprint (primary + rotation set)
// into the accepted pin list. Fails closed: a non-insecure dial with no
// usable pins refuses to talk rather than trusting an interceptor.
func (o *WSTLSOptions) pinSet() ([][]byte, error) {
	return buildPinSet(o.Fingerprint, o.Fingerprints)
}

func buildPinSet(primary string, extra []string) ([][]byte, error) {
	var pins [][]byte
	all := append([]string{primary}, extra...)
	for _, fp := range all {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		p, err := ParseFingerprint(fp)
		if err != nil {
			return nil, err
		}
		pins = append(pins, p)
	}
	if len(pins) == 0 {
		return nil, errors.New("transport: no certificate pin configured (refusing unverified TLS)")
	}
	return pins, nil
}

// VerifyPinSet accepts the presented leaf when its SHA-256 matches ANY
// configured pin (constant-shape comparison across the set).
func VerifyPinSet(pins [][]byte, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("transport: no certificates presented")
	}
	got := FingerprintCert(rawCerts[0])
	for _, pin := range pins {
		if len(pin) != len(got) {
			continue
		}
		match := true
		for i := range pin {
			if pin[i] != got[i] {
				match = false
				break
			}
		}
		if match {
			return nil
		}
	}
	return errors.New("transport: server certificate fingerprint mismatch")
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

	httpClient := newPinnedHTTPClient(tlsCfg, timeout, t.opt.ChromeHello)

	// No subprotocol and a browser-plausible User-Agent: under interception
	// this reads as an ordinary app's realtime channel, not a custom
	// protocol ("otu1" announced the tunnel by name; Go's stock UA announced
	// the toolchain). Deliberately NO Origin header: websocket servers
	// (including older relays) reject mismatched Origins with 403, which
	// would brick new clients against old servers mid-migration.
	// Client hints match the version story of the parroted hello: a Chrome
	// 133 hello with fetched-metadata headers absent (WS upgrades don't send
	// Sec-Fetch-*) would be a JPEG-artifact inconsistency under interception.
	hdr := http.Header{
		"User-Agent":         {browserUA},
		"Accept-Language":    {"en-US,en;q=0.9"},
		"sec-ch-ua":          {`"Not(A:Brand";v="24", "Chromium";v="133", "Google Chrome";v="133"`},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"Windows"`},
	}
	url := func(path string) string {
		return wsScheme + "://" + hostPort + path
	}
	dial := func(path string) (*websocket.Conn, *http.Response, error) {
		return websocket.Dial(dctx, url(path), &websocket.DialOptions{
			HTTPClient: httpClient,
			HTTPHeader: hdr,
		})
	}
	conn, _, err := dialWSWithLegacyFallback(dial, t.opt.wsPathOrDefault())
	if err != nil {
		return nil, fmt.Errorf("transport: websocket dial %s: %w", url(t.opt.wsPathOrDefault()), err)
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
				conn, err := tlsHandshake(ctx, raw, cfg, chrome)
				if err != nil {
					_ = raw.Close()
					return nil, err
				}
				return conn, nil
			},
			ForceAttemptHTTP2: false,
		},
		Timeout: timeout,
	}
}

// tlsHandshake upgrades raw with the pinned settings; chrome selects the uTLS
// Chrome parrot over the stock Go handshake. WebSocket upgrades ride
// HTTP/1.1, and a browser-plausible hello offering only h2 would tell a
// different story than the headers that follow — so the spec's ALPN is pinned
// to http/1.1. (Networks that classify hellos are defeated by the ssh
// fallback tier, not by hello tricks.)
func tlsHandshake(ctx context.Context, raw net.Conn, cfg *tls.Config, chrome bool) (net.Conn, error) {
	if !chrome {
		tconn := tls.Client(raw, cfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tconn, nil
	}
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
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
		ClientSessionCache:    utlsCache,
		// The static Chrome parrot carries no pre-shared-key slot, so there
		// is nothing to resume into yet: skip instead of panicking (uTLS
		// panics on cache-without-slot). Plain-TLS tiers resume normally;
		// wiring PSK into the parrot spec is future work (see
		// u_pre_shared_key.go Initializable).
		PreferSkipResumptionOnNilExtension: true,
	}
	uconn := utls.UClient(raw, ucfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("transport: apply chrome spec: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
		return nil, fmt.Errorf("transport: unexpected ALPN %q under Chrome hello", proto)
	}
	return uconn, nil
}
