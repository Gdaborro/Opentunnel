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
	if opt.PanelDB != nil {
		if clientToken == "" {
			// Legacy/no-token clients: synthetic approved entry for visibility.
			clientToken = "legacy-" + addrHost(stream.RemoteAddr())
			opt.PanelDB.CreateLegacyPeer(clientToken)
			_ = protocol.WriteToken(sec, "ok")
		} else {
			status, reason, kickExpires, _ := opt.PanelDB.CheckToken(clientToken)
			switch status {
			case "banned":
				_ = protocol.WriteToken(sec, "banned:"+reason)
				return
			case "pending", "expired":
				_ = protocol.WriteToken(sec, status)
				return
			case "kicked":
				_ = protocol.WriteToken(sec, "kicked:"+reason+":"+kickExpires)
			default: // approved
				_ = protocol.WriteToken(sec, "ok")
			}
			go opt.PanelDB.RecordTraffic(clientToken, 0, 0)
		}
	} else {
		// No panel: legacy mode, just ack
		_ = protocol.WriteToken(sec, "ok")
	}

	// One mode byte decides the session shape (protocol v3).
	mode := make([]byte, 1)
	if _, err := io.ReadFull(sec, mode); err != nil {
		return
	}
	switch mode[0] {
	case protocol.MuxMarker:
		opt.serveMuxSession(sec, clientToken)
	case protocol.UdpMarker:
		serveUDPStream(sec, opt.logger())
	default:
		relayTarget(mode[0], sec, opt, clientToken)
	}
}

// relayTarget performs the classic single-target exchange on rw and pipes it
// to the dialed upstream until both directions finish. Used by legacy
// sessions and by every multiplexed stream. Traffic is recorded per-token.
func relayTarget(atyp byte, rw deadlineRW, opt Options, token string) {
	defer rw.Close()

	target, err := protocol.ReadAddressWithATYP(atyp, rw)
	if err != nil {
		opt.logger().Printf("server: bad target: %v", err)
		return
	}

	// Site blocklist enforcement (footer-block page for HTTP-style clients).
	if opt.PanelDB != nil && target.Domain != "" && opt.PanelDB.IsBlocked(target.Domain) {
		_ = protocol.WriteTargetResponse(rw, protocol.StatusOK)
		buf := make([]byte, 256*1024)
		done := make(chan struct{}, 2)
		go func() { _, _ = io.CopyBuffer(io.Discard, rw, buf); done <- struct{}{} }()
		go func() { _, _ = io.CopyBuffer(io.Discard, rw, buf); done <- struct{}{} }()
		<-done
		<-done
		return
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
func (o Options) serveMuxSession(sec io.ReadWriteCloser, token string) {
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
			relayTarget(atyp[0], s, o, token)
		}(stream)
	}
}

var (
	replayOnce    sync.Once
	defaultReplay *protocol.ReplayCache
)

const DefaultDecoy = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;display:grid;place-items:center;height:100vh;background:#fafafa;color:#333}
main{text-align:center}h1{font-weight:600;font-size:2rem;margin-bottom:.5rem}p{color:#666}
</style>
</head>
<body><main><h1>Welcome</h1><p>Everything looks fine here.</p></main></body>
</html>
`
