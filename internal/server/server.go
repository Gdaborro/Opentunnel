// Package server implements the opentunnel relay: it terminates the
// transport, verifies handshakes, dials targets, and serves a decoy website
// to any request that is not a valid tunnel.
package server

import (
	"context"
	"crypto/subtle"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"
	"golang.org/x/time/rate"

	"opentunnel/internal/protocol"
	"opentunnel/internal/server/decoy"
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
	Token       string                // shared secret (no-panel mode; legacy fallback when AllowLegacyMaster)
	WSPath      string                // websocket endpoint path (default /ws)
	Logger      *log.Logger           // nil = std log
	DecoyHTML   []byte                // served to non-tunnel requests
	ReplayCache *protocol.ReplayCache // nil = default (10 min TTL, 100k salts)
	Guard       *Guard                // nil = DefaultGuard()
	// AllowRestrictedTargets disables the SSRF dial filter (loopback,
	// private, link-local/metadata, CGNAT ranges). Off by default.
	AllowRestrictedTargets bool
	// AllowLegacyMaster accepts the shared master token at the handshake
	// (migration aid while clients move to per-device tokens). The token is
	// never shipped in client binaries.
	AllowLegacyMaster bool
	PanelDB           interface { // optional panel DB for per-token checks
		CheckToken(token string) (status, reason, kickExpires string, err error)
		RecordTraffic(token string, up, down int64)
		IsBlocked(domain string) bool
		KillSwitch() bool
		PeerLimits(token string) (maxBps, quotaBytes int64)
		SetPeerIP(token, ip string)
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
	decoyHandler := decoy.Handler(opt.DecoyHTML)
	mux.Handle("/", decoyHandler)
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		release := opt.guard().Acquire(addrHost(r.RemoteAddr))
		if release == nil {
			// Over limit or banned: indistinguishable from the normal site.
			decoyHandler.ServeHTTP(w, r)
			return
		}
		defer release()

		if !isWebSocketUpgrade(r) {
			http.NotFound(w, r)
			return
		}
		// Global kill switch: refuse new tunnels outright.
		if opt.PanelDB != nil && opt.PanelDB.KillSwitch() {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
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

// verifyHandshakeToken maps a presented handshake token to a protocol
// status. With a panel DB the token is the client's per-device token and is
// validated against the panel (approval is the gate â€” no shared secret in
// the client binary). Without a panel, the static shared token is used.
func (o Options) verifyHandshakeToken(tok string) byte {
	if o.PanelDB == nil {
		return protocol.StaticVerifier(o.Token)(tok)
	}
	if o.AllowLegacyMaster && subtle.ConstantTimeCompare([]byte(tok), []byte(o.Token)) == 1 {
		return protocol.StatusOK // migration window for pre-device-token clients
	}
	status, _, _, _ := o.PanelDB.CheckToken(tok)
	switch status {
	case "approved", "kicked": // kicked: grace + block page handled in-channel
		return protocol.StatusOK
	case "pending":
		return protocol.StatusPending
	case "expired":
		return protocol.StatusExpired
	case "banned":
		return protocol.StatusBanned
	default:
		return protocol.StatusBadToken
	}
}

func handleSession(stream net.Conn, opt Options) {
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
	status, authTok, err := protocol.ReadAndVerifyHandshake(stream, stream, opt.verifyHandshakeToken)
	if err != nil || status != protocol.StatusOK {
		// Punish only genuine auth failures: pending/banned/expired peers
		// retry as part of normal flow and must not trip IP bans.
		if status == protocol.StatusBadToken || status == protocol.StatusBadVersion || err != nil {
			opt.guard().Punish(addrHost(stream.RemoteAddr()))
		}
		if err != nil {
			opt.logger().Printf("server: handshake rejected: %v", err)
		}
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

	// AEAD keys derive from the handshake token: the per-device token in
	// panel mode (per-device keys), the master token in legacy mode.
	sec, err := protocol.ServerSideSecureStream(stream, authTok, salt)
	if err != nil {
		return
	}

	// Per-client token (v4): always length-prefixed; "" = legacy client.
	clientToken, err := protocol.ReadToken(sec)
	if err != nil {
		opt.logger().Printf("server: bad client token: %v", err)
		return
	}
	if clientToken == "" {
		clientToken = authTok // very old clients: handshake token doubles as panel token
	}
	if opt.PanelDB != nil {
		go opt.PanelDB.SetPeerIP(clientToken, addrHost(stream.RemoteAddr()))
	}
	var peerStatus = "approved"
	var peerReason string
	if opt.PanelDB != nil {
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
		serveUDPStream(sec, opt)
	default:
		relayTarget(mode[0], sec, opt, clientToken, peerStatus, peerReason)
	}
}

// relayTarget performs the classic single-target exchange on rw and pipes it
// to the dialed upstream until both directions finish. Used by legacy
// sessions and by every multiplexed stream. Traffic is recorded per-token.
func relayTarget(atyp byte, rw deadlineRW, opt Options, token, peerStatus, peerReason string) {
	defer rw.Close()
	// Global kill switch: block every new stream while suspended.
	if opt.PanelDB != nil && opt.PanelDB.KillSwitch() {
		_ = protocol.WriteTargetResponse(rw, protocol.StatusBlocked)
		_ = protocol.WriteToken(rw, "blocked:service suspended (kill switch)")
		return
	}
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

	// Site blocklist enforcement - ISP level domain blocking with proper status.
	// IP-literal targets are matched too so blocklist entries can be IPs.
	if opt.PanelDB != nil {
		name := target.Domain
		if name == "" && target.IP != nil {
			name = target.IP.String()
		}
		if name != "" && opt.PanelDB.IsBlocked(name) {
			opt.logger().Printf("blocked %s for %s", name, shortToken(token))
			_ = protocol.WriteTargetResponse(rw, protocol.StatusBlocked)
			_ = protocol.WriteToken(rw, "blocked:"+name)
			return
		}
	}
	// Record aggregated visited site (privacy: domain only, no URL, count per peer)
	if opt.PanelDB != nil && token != "" && target.Domain != "" {
		go func(tok, dom string) {
			if db, ok := opt.PanelDB.(interface {
				Exec(string, ...interface{}) (interface{}, error)
			}); ok {
				_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS visits(token TEXT, domain TEXT, hits INTEGER DEFAULT 1, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(token, domain))`)
				_, _ = db.Exec(`INSERT INTO visits(token,domain,hits,last_seen) VALUES(?,?,1,datetime('now')) ON CONFLICT(token,domain) DO UPDATE SET hits=hits+1, last_seen=datetime('now')`, tok, dom)
			}
		}(token, target.Domain)
		// Abuse protection: per-peer rate limit - if same peer hits >100 domains in 10s, temp kick
		// (handled via Guard, but we also log)
		opt.logger().Printf("visit %s -> %s", shortToken(token), target.Domain)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !opt.AllowRestrictedTargets {
		dialer.Control = safeControl
	}
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

	// Per-device bandwidth cap (QoS): one shared token bucket paces both
	// directions of this stream. 0 = unlimited.
	var dst1, dst2 io.Writer = upstream, rw
	if opt.PanelDB != nil && token != "" {
		if maxBps, _ := opt.PanelDB.PeerLimits(token); maxBps > 0 {
			burst := int(maxBps)
			if burst < len(buf1) {
				burst = len(buf1)
			}
			lim := rate.NewLimiter(rate.Limit(maxBps), burst)
			dst1 = &limitedWriter{w: upstream, lim: lim}
			dst2 = &limitedWriter{w: rw, lim: lim}
		}
	}

	var n1, n2 int64
	done := make(chan struct{}, 2)
	go func() {
		n1, _ = io.CopyBuffer(dst1, rw, buf1)
		done <- struct{}{}
	}()
	go func() {
		n2, _ = io.CopyBuffer(dst2, upstream, buf2)
		done <- struct{}{}
	}()
	<-done
	<-done
	if opt.PanelDB != nil && token != "" {
		opt.PanelDB.RecordTraffic(token, n1, n2)
	}
}

// maxStreamsPerSession bounds concurrent smux streams on one tunnel session
// so an authenticated client cannot exhaust memory/fds by opening streams.
const maxStreamsPerSession = 256

// limitedWriter paces writes through a shared token bucket (per-device QoS).
type limitedWriter struct {
	w   io.Writer
	lim *rate.Limiter
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if n := len(p); n > 0 {
		if err := l.lim.WaitN(context.Background(), n); err != nil {
			return 0, err
		}
	}
	return l.w.Write(p)
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
	sem := make(chan struct{}, maxStreamsPerSession)
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			o.logger().Printf("server: stream cap (%d) reached â€” dropping stream", maxStreamsPerSession)
			stream.Close()
			continue
		}
		go func(s *smux.Stream) {
			defer func() { <-sem; s.Close() }()
			atyp := make([]byte, 1)
			if _, err := io.ReadFull(s, atyp); err != nil {
				return
			}
			if atyp[0] == protocol.UdpMarker {
				serveUDPStream(s, o)
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
