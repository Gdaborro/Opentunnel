// pinnedhttp.go: pinned HTTP client for control-plane traffic (panel status
// polls, health reports). Control requests land on the same IP as the
// tunnel — a stock Go handshake appearing next to a Chrome-mimicking tunnel
// flow is the cheapest of tells — so every request this binary makes follows
// the same pin/parrot story.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

// PinnedHTTPOptions configures the control-plane HTTP client.
type PinnedHTTPOptions struct {
	DialAddr    string // TCP target host[:port]; port 443 added when missing
	ServerName  string // TLS SNI + Host; defaults to the host part of DialAddr
	Fingerprint string // hex SHA-256 pin of the server certificate
	// Fingerprints are additional accepted pins (rotation survivors).
	Fingerprints []string
	Insecure     bool // dev only: skip pin verification entirely
	Timeout      time.Duration
	ChromeHello  bool // mimic Chrome's ClientHello (uTLS)
}

// NewPinnedHTTPClient builds an http.Client that always dials DialAddr —
// independent of each request URL's host — with the same pin/parrot settings
// as the ws-tls transport, so the URL can keep the operator's hostname while
// the TCP path follows server_ip entries (DNS-sinkhole resistant).
func NewPinnedHTTPClient(opt PinnedHTTPOptions) (*http.Client, error) {
	hostPort := opt.DialAddr
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		hostPort = net.JoinHostPort(hostPort, "443")
	}
	host, _, _ := net.SplitHostPort(hostPort)
	sni := host
	if opt.ServerName != "" {
		sni = opt.ServerName
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: opt.Insecure, // pin governs trust unless dev-insecure
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: sessionCache,
	}
	if !opt.Insecure {
		pins, perr := buildPinSet(opt.Fingerprint, opt.Fingerprints)
		if perr != nil {
			// Benign-looking half-configured pins must not degrade to
			// unverified TLS: without a pin the caller gets a client that
			// refuses to talk (error here), never one an interceptor can
			// sit beneath.
			return nil, fmt.Errorf("transport: pinned http client %s: %w", sni, perr)
		}
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return VerifyPinSet(pins, rawCerts)
		}
	}
	d := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				raw, err := d.DialContext(ctx, "tcp", hostPort)
				if err != nil {
					return nil, err
				}
				conn, err := tlsHandshake(ctx, raw, cfg, opt.ChromeHello)
				if err != nil {
					_ = raw.Close()
					return nil, err
				}
				return conn, nil
			},
			ForceAttemptHTTP2: false,
		},
	}, nil
}
