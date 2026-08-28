// Package server implements the opentunnel relay: it terminates the
// transport, verifies handshakes, dials targets, and serves a decoy website
// to any request that is not a valid tunnel.
package server

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"

	"opentunnel/internal/protocol"
)

// deadlineRW is the read-write stream contract for target relaying.
type deadlineRW interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
}

// isWebSocketUpgrade mirrors RFC 6455 handshake detection without relying on
// a library helper.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

type Options struct {
	Token       string                // shared secret (fallback, also inner AEAD key)
	WSPath      string                // websocket endpoint path (default /ws)
	Logger      *log.Logger           // nil = std log
	DecoyHTML   []byte                // served to non-tunnel requests
	ReplayCache *protocol.ReplayCache // nil = default (10 min TTL, 100k salts)
	Guard       *Guard                // nil = DefaultGuard()
	PanelDB     interface { // optional panel DB for per-token checks
		CheckToken(token string) (status, reason, kickExpires string, err error)
		RecordTraffic(token string, up, down int64)
		IsBlocked(domain string) bool
		CreateLegacyPeer(ip string)
	}
}

func (o *Options) guard() *Guard {
	if o.Guard != nil {
		return o.Guard
	}
	guardOnce.Do(func() { defaultGuard = DefaultGuard() })
	return defaultGuard
}

var (
	guardOnce    sync.Once
	defaultGuard *Guard
)

func (o *Options) wsPath() string {
	if o.WSPath == "" {
		return "/ws"
	}
	return o.WSPath
}

func (o *Options) logger() *log.Logger {
	if o.Logger == nil {
		return log.Default()
	}
	return o.Logger
}

// Handler returns an http.Handler that upgrades tunnel requests on wsPath and
// serves the decoy page for everything else. Mount behind a TLS listener.
func Handler(opt Options) http.Handler {
	mux := http.NewServeMux()
	path := opt.wsPath()
	if path[0] != '/' {
		path = "/" + path
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := opt.DecoyHTML
		if page == nil {
			page = []byte(DefaultDecoy)
		}
		_, _ = w.Write(page)
	})
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		release := opt.guard().Acquire(addrHost(r.RemoteAddr))
		if release == nil {
			// Over limit or banned: indistinguishable from the normal site.
			page := opt.DecoyHTML
			if page == nil {
				page = []byte(DefaultDecoy)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(page)
			return
		}
		defer release()

		if !isWebSocketUpgrade(r) {
			http.NotFound(w, r)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"otu1"},
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		stream := websocket.NetConn(r.Context(), conn, websocket.MessageBinary)
		handleSession(stream, opt)
	})
	return mux
}

func handleSession(stream net.Conn, opt Options) {
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
	status, err := protocol.ReadAndVerifyHandshake(stream, stream, opt.Token)
	if err != nil || status != protocol.StatusOK {
		opt.guard().Punish(addrHost(stream.RemoteAddr()))
		opt.logger().Printf("server: handshake rejected: %v", err)
		return
	}

	salt, err := protocol.ReadSalt(stream)
	if err != nil {
		return // silent close for malformed sessions
	}
	cache := opt.ReplayCache
	if cache == nil {
		replayOnce.Do(func() { defaultReplay = protocol.NewReplayCache(10*time.Minute, 100_000) })
		cache = defaultReplay
	}
	if !cache.CheckAndAdd(salt) {
		opt.logger().Printf("server: replayed session salt ??? dropped")
		return
	}

	sec, err := protocol.ServerSideSecureStream(stream, opt.Token, salt)
	if err != nil {
		return
	}

	// Per-client token (v4): always length-prefixed; "" = legacy client.
	clientToken, err := protocol.ReadToken(sec)
	if err != nil {
		opt.logger().Printf("server: bad client token: %v", err)
		return
	}
	var peerStatus = "approved"
	var peerReason string
	if opt.PanelDB != nil {
		if clientToken == "" {
			clientToken = "legacy-" + addrHost(stream.RemoteAddr())
			opt.PanelDB.CreateLegacyPeer(clientToken)
			_ = protocol.WriteToken(sec, "ok")
			peerStatus = "approved"
		} else {
			status, reason, kickExpires, _ := opt.PanelDB.CheckToken(clientToken)
			switch status {
			case "banned":
				_ = protocol.WriteToken(sec, "banned:"+reason)
				peerStatus = "banned"
				peerReason = reason
			case "pending", "expired":
				_ = protocol.WriteToken(sec, status)
				return
			case "kicked":
				_ = protocol.WriteToken(sec, "kicked:"+reason+":"+kickExpires)
				peerStatus = "kicked"
				peerReason = reason
				if strings.HasPrefix(reason, "silent:") {
					peerStatus = "kicked-silent"
				}
			default:
				_ = protocol.WriteToken(sec, "ok")
				peerStatus = "approved"
			}
			go opt.PanelDB.RecordTraffic(clientToken, 0, 0)
		}
	} else {
		_ = protocol.WriteToken(sec, "ok")
		peerStatus = "approved"
	}
	// For banned/kicked, schedule 10min kick - hard to bypass, easy to unban via panel
	if peerStatus == "banned" || peerStatus == "kicked" || peerStatus == "kicked-silent" {
		go func(s net.Conn, tok string) {
			time.Sleep(10 * time.Minute)
			s.Close()
			// Also ensure peer is still banned/kicked, if kicked silent we don't log
			if peerStatus == "kicked" || peerStatus == "kicked-silent" {
				// reaper will auto-approve kicked after 10m, but we also close
			}
		}(sec, clientToken)
	}

	// One mode byte decides the session shape (protocol v3).
	mode := make([]byte, 1)
	if _, err := io.ReadFull(sec, mode); err != nil {
		return
	}
	switch mode[0] {
	case protocol.MuxMarker:
		opt.serveMuxSession(sec, clientToken, peerStatus, peerReason)
	case protocol.UdpMarker:
		serveUDPStream(sec, opt.logger())
	default:
		relayTarget(mode[0], sec, opt, clientToken, peerStatus, peerReason)
	}
}

// relayTarget performs the classic single-target exchange on rw and pipes it
// to the dialed upstream until both directions finish. Used by legacy
// sessions and by every multiplexed stream. Traffic is recorded per-token.
func relayTarget(atyp byte, rw deadlineRW, opt Options, token, peerStatus, peerReason string) {
	defer rw.Close()
	// ISP-level ban/kick handling
	if peerStatus == "banned" {
		_ = protocol.WriteTargetResponse(rw, protocol.StatusBlocked)
		_ = protocol.WriteToken(rw, "banned:"+peerReason)
		return
	}
	if peerStatus == "kicked" {
		_ = protocol.WriteTargetResponse(rw, protocol.StatusBlocked)
		_ = protocol.WriteToken(rw, "kicked:"+peerReason)
		return
	}
	if peerStatus == "kicked-silent" {
		_ = protocol.WriteTargetResponse(rw, protocol.StatusBlocked)
		_ = protocol.WriteToken(rw, "kicked-silent")
		return
	}

	target, err := protocol.ReadAddressWithATYP(atyp, rw)
	if err != nil {
		opt.logger().Printf("server: bad target: %v", err)
		return
	}

	// Site blocklist enforcement - ISP level domain blocking with proper status
	if opt.PanelDB != nil && target.Domain != "" && opt.PanelDB.IsBlocked(target.Domain) {
		opt.logger().Printf("blocked %s for %s", target.Domain, token)
		_ = protocol.WriteTargetResponse(rw, protocol.StatusBlocked)
		_ = protocol.WriteToken(rw, "blocked:"+target.Domain)
		return
	}
	// Record aggregated visited site (privacy: domain only, no URL, count per peer)
	if opt.PanelDB != nil && token != "" && target.Domain != "" {
		go func(tok, dom string) {
			if db, ok := opt.PanelDB.(interface{ Exec(string, ...interface{}) (interface{}, error) }); ok {
				_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS visits(token TEXT, domain TEXT, hits INTEGER DEFAULT 1, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(token, domain))`)
				_, _ = db.Exec(`INSERT INTO visits(token,domain,hits,last_seen) VALUES(?,?,1,datetime('now')) ON CONFLICT(token,domain) DO UPDATE SET hits=hits+1, last_seen=datetime('now')`, tok, dom)
			}
		}(token, target.Domain)
		// Abuse protection: per-peer rate limit - if same peer hits >100 domains in 10s, temp kick
		// (handled via Guard, but we also log)
		opt.logger().Printf("visit %s -> %s", shortToken(token), target.Domain)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.Dial("tcp", target.HostPort())
	if err != nil {
		_ = protocol.WriteTargetResponse(rw, protocol.StatusDialFailed)
		opt.logger().Printf("server: dial %s failed: %v", target, err)
		return
	}
	defer upstream.Close()

	if err := protocol.WriteTargetResponse(rw, protocol.StatusOK); err != nil {
		return
	}
	_ = rw.SetDeadline(time.Now().Add(10 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
	_ = upstream.(*net.TCPConn).SetNoDelay(true)

	// 256 KiB copy buffers keep syscalls (and per-frame overhead) low on
	// high-BDP paths; both directions must finish before teardown.
	buf1 := make([]byte, 256*1024)
	buf2 := make([]byte, 256*1024)
	var n1, n2 int64
	done := make(chan struct{}, 2)
	go func() {
		n1, _ = io.CopyBuffer(upstream, rw, buf1)
		done <- struct{}{}
	}()
	go func() {
		n2, _ = io.CopyBuffer(rw, upstream, buf2)
		done <- struct{}{}
	}()
	<-done
	<-done
	if opt.PanelDB != nil && token != "" {
		opt.PanelDB.RecordTraffic(token, n1, n2)
	}
}

// serveMuxSession upgrades an authenticated secure stream into a smux
// session; every stream inside carries one relayTarget exchange.
func (o Options) serveMuxSession(sec io.ReadWriteCloser, token, peerStatus, peerReason string) {
	sess, err := smux.Server(sec, protocol.MuxConfig())
	if err != nil {
		o.logger().Printf("server: mux setup failed: %v", err)
		return
	}
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go func(s *smux.Stream) {
			defer s.Close()
			atyp := make([]byte, 1)
			if _, err := io.ReadFull(s, atyp); err != nil {
				return
			}
			if atyp[0] == protocol.UdpMarker {
				serveUDPStream(s, o.logger())
				return
			}
			relayTarget(atyp[0], s, o, token, peerStatus, peerReason)
		}(stream)
	}
}

var (
	replayOnce    sync.Once
	defaultReplay *protocol.ReplayCache
)

// shortToken returns an 8-char log prefix without assuming token length
// (tokens are client-chosen strings; slicing blindly could panic).
func shortToken(t string) string {
	if len(t) > 8 {
		return t[:8]
	}
	return t
}

const DefaultDecoy = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aborro — Systems &amp; Cloud</title>
<meta name="description" content="Aborro Systems — small team, cloud infrastructure, private networking, Oracle Cloud specialist.">
<style>
:root{--bg:#f8fafc;--card:#ffffff;--text:#0f172a;--muted:#64748b;--line:#e2e8f0}
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:var(--bg);color:var(--text);line-height:1.6}
header{max-width:960px;margin:0 auto;padding:28px 20px;display:flex;justify-content:space-between;align-items:center}
nav a{color:var(--muted);text-decoration:none;margin-left:18px;font-size:0.9rem}
nav a:hover{color:var(--text)}
.hero{max-width:960px;margin:24px auto;padding:28px 20px;display:grid;grid-template-columns:1.2fr 0.8fr;gap:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;box-shadow:0 2px 8px rgba(15,23,42,0.04)}
h1{margin:0 0 8px;font-size:1.8rem;letter-spacing:-0.02em}p{margin:0;color:var(--muted)}
.grid{max-width:960px;margin:0 auto;padding:0 20px;display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.footer{max-width:960px;margin:32px auto;padding:0 20px;color:var(--muted);font-size:0.85em}
@media(max-width:800px){.hero{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header><div style="font-weight:700;letter-spacing:-0.02em">aborro<span style="color:#6366f1">.systems</span></div><nav><a href="/">Home</a><a href="/about">About</a><a href="/contact">Contact</a></nav></header>
<section class="hero">
  <div class="card"><h1>Infrastructure, quietly done.</h1><p>We run small, reliable workloads on Oracle Cloud — Terraform, observability, and private links. No tracking, no ads. Just systems that stay up.</p><p style="margin-top:12px"><a href="/contact" style="display:inline-block;background:#0f172a;color:white;padding:8px 12px;border-radius:8px;text-decoration:none">Get in touch</a></p></div>
  <div class="card"><h3 style="margin:0 0 8px">Status</h3><p>All systems operational. Last deploy: 2026-08-27. Uptime 99.9%.</p><p style="margin-top:8px;color:#10b981">● cdn.aborro.dev — edge</p><p>● vpn.aborro.dev — relay</p></div>
</section>
<section class="grid">
  <div class="card"><h3>Cloud</h3><p>Oracle Cloud, region ap-sydney-1. Minimal foot print, auto-patched, log-rotated.</p></div>
  <div class="card"><h3>Security</h3><p>ACME TLS, strict headers, daily apt upgrades, unattended reboots.</p></div>
  <div class="card"><h3>Contact</h3><p>hello@aborro.dev — Sydney, AU. We reply within a day.</p></div>
</section>
<footer class="footer">© 2026 Aborro Systems Pty Ltd · ABN 12 345 678 901 · Sydney</footer>
</body>
</html>
`
