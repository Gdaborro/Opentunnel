// Package proxy implements client-side inbound listeners: a local SOCKS5 and
// HTTP proxy that forward application traffic into the tunnel.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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
			// For HTTP (80) we can show ISP block page (plain HTTP). For TLS (443) HSTS would reject self-signed cert,
			// so just send SOCKS failure 0x02 (connection not allowed) — Firefox shows clean "Unable to connect" not PR_CONNECT_ABORTED_ERROR.
			// The block reason is always visible in panel Blocklist/Visits and System tab. HTTP proxy CONNECT already shows 403 page for HTTPS.
			if addr != nil && addr.Port == 80 {
				_, _ = conn.Write([]byte{socksVer, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				serveSocksBlockPage(conn, addr, err)
			} else {
				_, _ = conn.Write([]byte{socksVer, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}
			if logErr != nil {
				logThrottled(logErr, "blocked:"+addr.String(), 60*time.Second, "socks: blocked %s: %v", addr, err)
			}
			return
		}
		_, _ = conn.Write([]byte{socksVer, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		logThrottled(logErr, "tunnel:"+addr.String(), 60*time.Second, "socks: tunnel %s: %v", addr, err)
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
	kind := "blocked"
	badgeClass := "badge-outline"
	badgeLabel := "Blocked"
	title := "Access blocked"
	desc := ""
	if err != nil && strings.Contains(err.Error(), "banned:") {
		kind = "banned"
		badgeClass = "badge-destructive"
		badgeLabel = "Banned"
		title = "Access suspended"
		desc = fmt.Sprintf("This device is <strong>banned</strong>: %s. Every site shows this page until an administrator lifts the ban.", escHTML(reason))
	} else if err != nil && strings.Contains(err.Error(), "kicked") {
		if strings.Contains(err.Error(), "silent") {
			return "" // silent kick - no page
		}
		kind = "kicked"
		badgeClass = "badge-destructive"
		badgeLabel = "Paused"
		title = "Access paused"
		desc = fmt.Sprintf("This device is temporarily <strong>paused</strong>: %s. Access resumes automatically.", escHTML(reason))
	} else {
		desc = fmt.Sprintf("The domain <strong>%s</strong> is blocked by network policy%sSubdomains are included. Contact your administrator to request access.", escHTML(domain), reasonSuffix(reason))
	}
	_ = kind
	return "<!DOCTYPE html><html lang=\"en\" class=\"dark\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
		"<title>" + escHTML(title) + " — otu</title>" +
		"<style>" +
		":root{--background:oklch(0.145 0 0);--foreground:oklch(0.985 0 0);" +
		"--card:oklch(0.205 0 0);--card-foreground:oklch(0.985 0 0);" +
		"--primary:oklch(0.922 0 0);--primary-foreground:oklch(0.205 0 0);" +
		"--muted:oklch(0.269 0 0);--muted-foreground:oklch(0.708 0 0);" +
		"--destructive:oklch(0.704 0.191 22.216);--border:oklch(1 0 0 / 10%);--radius:0.625rem}" +
		"*{box-sizing:border-box;margin:0}" +
		"body{background:var(--background);color:var(--foreground);" +
		"font-family:ui-sans-serif,system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;" +
		"min-height:100vh;display:grid;place-items:center;padding:1rem;-webkit-font-smoothing:antialiased}" +
		".card{display:flex;flex-direction:column;gap:1.5rem;width:100%;max-width:26rem;" +
		"background:var(--card);color:var(--card-foreground);border-radius:1rem;" +
		"padding:1.5rem;box-shadow:0 0 0 1px oklch(0.985 0 0 / 10%);font-size:0.875rem;line-height:1.5}" +
		".head{display:flex;align-items:center;gap:0.75rem}" +
		".icon{flex:none;display:grid;place-items:center;width:2.25rem;height:2.25rem;border-radius:0.75rem;" +
		"background:oklch(0.704 0.191 22.216 / 0.12);color:var(--destructive)}" +
		".icon svg{width:1.125rem;height:1.125rem}" +
		".badge{display:inline-flex;align-items:center;height:1.25rem;border-radius:9999px;" +
		"padding:0 0.5rem;font-size:0.75rem;font-weight:500;white-space:nowrap}" +
		".badge-outline{border:1px solid var(--border);color:var(--foreground);background:oklch(0.922 0 0 / 0.03)}" +
		".badge-destructive{color:var(--destructive);background:oklch(0.704 0.191 22.216 / 0.12)}" +
		"h1{font-size:1.25rem;font-weight:600;letter-spacing:-0.01em;line-height:1.4}" +
		".desc{color:var(--muted-foreground)}.desc strong{color:var(--foreground);font-weight:600}" +
		".foot{border-top:1px solid var(--border);padding-top:1rem;font-size:0.75rem;color:var(--muted-foreground);" +
		"display:flex;align-items:center;justify-content:space-between}" +
		".brand{font-weight:600;color:var(--foreground)}" +
		"</style></head><body><main class=\"card\" role=\"alert\">" +
		"<div class=\"head\"><span class=\"icon\">" +
		"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\"/><path d=\"M12 8v4\"/><path d=\"M12 16h.01\"/></svg>" +
		"</span><span class=\"badge " + badgeClass + "\">" + badgeLabel + "</span></div>" +
		"<div><h1>" + escHTML(title) + "</h1><p class=\"desc\">" + desc + "</p></div>" +
		"<div class=\"foot\"><span class=\"brand\">otu</span><span>network protection</span></div>" +
		"</main></body></html>"
}

func reasonSuffix(reason string) string {
	if reason == "" || reason == "blocked" {
		return " "
	}
	return ": " + escHTML(reason) + ". "
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
				logThrottled(logErr, "blocked:"+addr.String(), 60*time.Second, "http: blocked %s: %v", addr, err)
				return
			}
			logThrottled(logErr, "tunnel:"+addr.String(), 60*time.Second, "http: tunnel %s: %v", addr, err)
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
			logThrottled(logErr, "blocked:"+addr.String(), 60*time.Second, "http: blocked %s: %v", addr, err)
			return
		}
		httpRespondError(conn, 502, "tunnel unavailable")
		logThrottled(logErr, "tunnel:"+addr.String(), 60*time.Second, "http: tunnel %s: %v", addr, err)
		return
	}
	defer up.Close()
	line := req.method + " " + req.pathOnly() + " " + req.proto + "\r\n"
	if _, err := io.WriteString(up, line+req.restOfHeaders()); err != nil {
		return
	}
	Pipe(ctx, conn, up)
}
