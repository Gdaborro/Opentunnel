// Package proxy implements client-side inbound listeners: a local SOCKS5 and
// HTTP proxy that forward application traffic into the tunnel.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"opentunnel/internal/protocol"
)

// Dialer produces an authenticated tunnel connection routed to target.
type Dialer interface {
	DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error)
}

// UDPDialer optionally provides the framed UDP relay stream
// (implemented by clients with mux enabled).
type UDPDialer interface {
	OpenUDPRelay(ctx context.Context) (net.Conn, error)
}

const (
	socksVer      = 5
	socksAuthNone = 0x00
	socksCmdConn  = 0x01
	socksCmdUDP   = 0x03
)

// ServeSOCKS5 accepts connections on ln until it closes.
func ServeSOCKS5(ctx context.Context, ln net.Listener, d Dialer, logErr *log.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && logErr != nil {
				logErr.Printf("socks: accept: %v", err)
			}
			return
		}
		go handleSocks(ctx, conn, d, logErr)
	}
}

func handleSocks(ctx context.Context, conn net.Conn, d Dialer, logErr *log.Logger) {
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	// Greeting: VER NMETHODS METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != socksVer {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == socksAuthNone {
			ok = true
			break
		}
	}
	if _, err := conn.Write([]byte{socksVer, map[bool]byte{true: 0x00, false: 0xFF}[ok]}); err != nil || !ok {
		return
	}
	// Request: VER CMD RSV then Address
	req := make([]byte, 3)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != socksVer || req[2] != 0x00 {
		_, _ = conn.Write([]byte{socksVer, 0x01, 0x00})
		return
	}
	switch req[1] {
	case socksCmdConn:
	case socksCmdUDP:
		ud, ok := d.(UDPDialer)
		if !ok {
			_, _ = conn.Write([]byte{socksVer, 0x07, 0x00}) // command not supported
			return
		}
		handleUDPAssociate(ctx, conn, ud, logErr)
		return
	default:
		_, _ = conn.Write([]byte{socksVer, 0x07, 0x00}) // command not supported
		return
	}
	addr, err := protocol.ReadAddress(conn)
	if err != nil {
		return
	}
	// ISP-level: try to dial first, so blocked/banned can be signaled
	up, err := d.DialTunnel(ctx, addr)
	if err != nil {
		if isBlockedErr(err) {
			// For SOCKS, send success first (as if tunnel established), then send block page as if from target
			// This way browser sees HTTP 403 instead of SOCKS failure or PR_CONNECT_RESET_ERROR
			_, _ = conn.Write([]byte{socksVer, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			serveSocksBlockPage(conn, addr, err)
			if logErr != nil {
				logErr.Printf("socks: blocked %s: %v", addr, err)
			}
			return
		}
		_, _ = conn.Write([]byte{socksVer, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if logErr != nil {
			logErr.Printf("socks: tunnel %s: %v", addr, err)
		}
		return
	}
	_, _ = conn.Write([]byte{socksVer, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	defer up.Close()
	Pipe(ctx, conn, up)
}

// ServeHTTPProxy serves HTTP CONNECT plus absolute-form requests.
func ServeHTTPProxy(ctx context.Context, ln net.Listener, d Dialer, logErr *log.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && logErr != nil {
				logErr.Printf("http-proxy: accept: %v", err)
			}
			return
		}
		go handleHTTPOne(ctx, conn, d, logErr)
	}
}

func isBlockedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "banned:") || strings.Contains(s, "kicked:") || strings.Contains(s, "blocked:") || strings.Contains(s, "StatusBlocked") || strings.Contains(s, "blocked")
}

func blockReason(err error) string {
	if err == nil {
		return "blocked by policy"
	}
	s := err.Error()
	for _, p := range []string{"banned:", "kicked:", "blocked:", "kicked-silent:"} {
		if idx := strings.Index(s, p); idx != -1 {
			reason := s[idx+len(p):]
			if i := strings.Index(reason, ":"); i != -1 && p == "kicked:" {
				// handle silent prefix inside
			}
			// trim trailing quotes/brackets
			reason = strings.Trim(reason, "\"' ")
			if reason == "" {
				reason = p[:len(p)-1]
			}
			return reason
		}
	}
	// also try StatusBlocked
	if strings.Contains(s, "8") {
		return "blocked"
	}
	return "blocked by policy"
}

func serveBlockPageHTML(addr *protocol.Address, err error) string {
	domain := ""
	if addr != nil {
		if addr.Domain != "" {
			domain = addr.Domain
		} else if addr.IP != nil {
			domain = addr.IP.String()
		}
	}
	reason := blockReason(err)
	kind := "Blocked"
	if err != nil && strings.Contains(err.Error(), "banned:") {
		kind = "Banned"
	} else if err != nil && strings.Contains(err.Error(), "kicked") {
		kind = "Kicked"
	}
	title := kind + " by ISP"
	msg := ""
	if kind == "Banned" {
		msg = fmt.Sprintf("You are <b>banned</b>: %s<br>Any site will show this page.<br>You will be kicked off the network in 10 minutes.<br>Hard to bypass (fingerprint+IP banned).<br>Easy to unban via panel.", escHTML(reason))
	} else if kind == "Kicked" {
		if strings.Contains(err.Error(), "silent") {
			return "" // silent kick - no page
		}
		msg = fmt.Sprintf("You are <b>kicked</b>: %s<br>You will be disconnected in 10 minutes.<br>Silent kick available for stealth.", escHTML(reason))
	} else {
		msg = fmt.Sprintf("Domain <b>%s</b> is blocked: %s<br>Contact admin to unblock. Subdomains also blocked.", escHTML(domain), escHTML(reason))
	}
	return fmt.Sprintf("<html><head><title>%s</title><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><style>body{font-family:system-ui,sans-serif;background:#f8fafc;margin:0;display:grid;place-items:center;min-height:100vh;color:#1e293b}main{background:white;border:1px solid #e2e8f0;border-radius:12px;padding:2rem;max-width:520px;box-shadow:0 4px 12px rgba(0,0,0,0.05)}h1{margin:0 0 0.5rem;font-size:1.4rem}p{color:#475569;line-height:1.5}</style></head><body><main><h1>🚫 %s</h1><p>%s</p><p style=\"font-size:0.85em;color:#64748b;margin-top:1rem\">opentunnel ISP • aggregated visits only (privacy) • abuse protection active</p></main></body></html>", escHTML(title), escHTML(title), msg)
}

func escHTML(s string) string {
	r := strings.ReplaceAll(s, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	r = strings.ReplaceAll(r, ">", "&gt;")
	r = strings.ReplaceAll(r, "\"", "&quot;")
	return r
}

func serveSocksBlockPage(conn net.Conn, addr *protocol.Address, err error) {
	if err != nil && strings.Contains(err.Error(), "kicked-silent") {
		return // silent - just close, no page
	}
	// For HSTS sites (facebook.com etc), a self-signed TLS cert triggers MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT with no bypass.
	// Instead, for TLS (443) just close cleanly — browser shows PR_CONNECT_RESET_ERROR which we avoid by not sending HTTP over TLS.
	// The ISP block page is still shown for HTTP (80) and for HTTPS via HTTP CONNECT (which returns 403 correctly).
	// We also log the blocked attempt so the panel's Blocklist/Visits shows it, and System tab explains HSTS.
	if addr != nil && (addr.Port == 443 || addr.Port == 8443) {
		// Don't try TLS MITM for HSTS — just close. The dashboard will show the blocked domain with reason.
		return
	}
	page := serveBlockPageHTML(addr, err)
	if page == "" {
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: " + fmt.Sprintf("%d", len(page)) + "\r\n\r\n" + page))
}

var blockCertCache = make(map[string]tls.Certificate)
var blockCertKey *rsa.PrivateKey

func generateBlockCert(domain string) (tls.Certificate, error) {
	if c, ok := blockCertCache[domain]; ok {
		return c, nil
	}
	if blockCertKey == nil {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return tls.Certificate{}, err
		}
		blockCertKey = k
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: domain, Organization: []string{"opentunnel ISP"}},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{domain},
	}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &blockCertKey.PublicKey, blockCertKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(blockCertKey)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	blockCertCache[domain] = cert
	return cert, nil
}

func serveHTTPBlockPage(conn net.Conn, addr *protocol.Address, err error) {
	if err != nil && strings.Contains(err.Error(), "kicked-silent") {
		_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
		return
	}
	page := serveBlockPageHTML(addr, err)
	if page == "" {
		_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
		return
	}
	// For CONNECT (HTTPS) we send 403 with block page directly - browser will display it instead of doing TLS
	// This avoids PR_CONNECT_RESET_ERROR and shows reason. No SSL error because we never do TLS.
	_, _ = conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: " + fmt.Sprintf("%d", len(page)) + "\r\n\r\n" + page))
}

func handleHTTPOne(ctx context.Context, conn net.Conn, d Dialer, logErr *log.Logger) {
	defer conn.Close()
	req, err := httpReadRequest(conn)
	if err != nil {
		return
	}
	var addr *protocol.Address
	if req.method == httpMethodConnect {
		addr, err = authorityToAddr(req.target)
	} else {
		addr, err = absoluteURLToAddr(req)
	}
	if err != nil {
		httpRespondError(conn, 400, "bad request")
		return
	}
	if req.method == httpMethodConnect {
		up, err := d.DialTunnel(ctx, addr)
		if err != nil {
			if isBlockedErr(err) {
				// For CONNECT (usually TLS), just close - browser will show connection reset, but also try to serve block page via HTTP
				// For better UX, close and let browser retry as HTTP block page
				serveHTTPBlockPage(conn, addr, err)
				if logErr != nil {
					logErr.Printf("http: blocked %s: %v", addr, err)
				}
				return
			}
			if logErr != nil {
				logErr.Printf("http: tunnel %s: %v", addr, err)
			}
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		defer up.Close()
		Pipe(ctx, conn, up)
		return
	}
	// Absolute-form request: rewrite to origin-form and relay raw bytes.
	up, err := d.DialTunnel(ctx, addr)
	if err != nil {
		if isBlockedErr(err) {
			serveHTTPBlockPage(conn, addr, err)
			return
		}
		httpRespondError(conn, 502, "tunnel unavailable")
		return
	}
	defer up.Close()
	line := req.method + " " + req.pathOnly() + " " + req.proto + "\r\n"
	if _, err := io.WriteString(up, line+req.restOfHeaders()); err != nil {
		return
	}
	Pipe(ctx, conn, up)
}
