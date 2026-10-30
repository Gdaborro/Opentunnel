// Package server implements the opentunnel relay: it terminates the
// transport, verifies handshakes, dials targets, and serves a decoy website
// to any request that is not a valid tunnel.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	"opentunnel/internal/metrics"
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
		BlockWhy(domain string) string
		KillSwitch() bool
		// Kill-switch detail: the admin's reason (shown on the client's
		// traffic-down page) and the token allowlist that keeps the
		// operator's own devices tunneling while the switch is engaged.
		KillSwitchReason() string
		KillSwitchAllow(token string) bool
		PeerLimits(token string) (maxBps, quotaBytes int64)
		// SSH-tier containment (sshtier.go): sustained cap and daily byte
		// budget for the ssh transport's ingress, plus the post-budget
		// trickle rate. All 0 = disabled.
		SSHTierLimits() (maxBps, dailyBytes, trickleBps int64)
		SetPeerIP(token, ip string)
		// Control channel (v0.9.23): in-band status/health mirroring the
		// panel's public token API for devices on TLS-intercepting networks.
		RecordHealth(token, version, osName, arch string, cpuPct, memPct, tempC float64, uptimeS int64, latencyMs, jitterMs, probeLossPct float64)
		BanReason(token string) string
		TouchPeer(token string)
		KnownPeer(token string) bool
		RecordVisit(token, domain string)
		// V5 handshake binding: the SSH public key registered for a token
		// (proof-of-possession check) and security alerting.
		SSHPubKey(token string) string
		RecordAlert(severity, kind, message string)
		// Sticky per-peer v5 upgrade latch (downgrade gate).
		MarkV5(token string)
		V5Seen(token string) bool
	}
	// CurrentPin, when set, returns the relay's CURRENT leaf certificate
	// fingerprint (hex). Every control response carries it so clients
	// survive certificate rotation (LE renews ~every 60-90 days; a stale
	// pin would otherwise brick every client at renewal).
	CurrentPin func() string
	// SSHPublicHost, when set, is announced in every control response
	// (CtrlResponse.SSHHost): the plain A record clients should dial for
	// the ssh last-resort tier once the tunnel domain is CDN-fronted
	// (CDNs do not proxy port 22). Clients learn and persist it in-band.
	SSHPublicHost string
	// TrustCloudflareIPs resolves real client IPs from CF-Connecting-IP
	// when the TCP peer is a Cloudflare edge (CDN front). Guards, GeoIP
	// and rate limits then see the client, not the CDN.
	TrustCloudflareIPs bool
	// RequireV5After, when non-zero, refuses v4 handshakes from every
	// key-registered peer after that date — the auto-sunset for the
	// migration window. The per-peer v5_seen gate is always active
	// regardless.
	RequireV5After time.Time
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
		return protocol.DefaultWSPath
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
	wsHandler := func(w http.ResponseWriter, r *http.Request) {
		peerIP := ResolveClientIP(r, opt.TrustCloudflareIPs)
		// Ingress marker (sshtier.go): set by WithIngress on the loopback
		// listener the ssh transport forwards into; public arrivals are "".
		ingress := ingressFrom(r)
		// HTTP/3 arrivals (ProtoMajor 3): the h3 transport tier tunnels
		// the protocol over a streaming request — no WebSocket upgrade
		// exists on that path. Same guard, same session machinery.
		if r.ProtoMajor == 3 {
			release := opt.guard().Acquire(peerIP)
			if release == nil {
				decoyHandler.ServeHTTP(w, r)
				return
			}
			defer release()
			// NO upgrade-level kill-switch block: sessions must establish
			// so clients can render the traffic-down page, and the
			// allowlisted operator device must be able to connect.
			// Enforcement is per-stream in relayTarget/serveUDPStream.
			flusher, _ := w.(http.Flusher)
			w.Header().Set("Content-Type", "application/octet-stream")
			// Respond immediately: the client's dial cannot complete
			// until headers arrive, and the protocol handshake bytes
			// only flow after the dial returns. Headers first, then the
			// session machinery reads from the request body.
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}
			handleSession(&h3ServerConn{Reader: r.Body, Writer: w, Flusher: flusher}, opt, peerIP, ingress)
			return
		}
		release := opt.guard().Acquire(peerIP)
		if release == nil {
			// Over limit or banned: indistinguishable from the normal site.
			decoyHandler.ServeHTTP(w, r)
			return
		}
		defer release()

		if !isWebSocketUpgrade(r) {
			// Not a tunnel after all: serve exactly what every other path
			// serves. A Go-native "404 page not found" here would both
			// fingerprint the server and mark the endpoint for active probers.
			decoyHandler.ServeHTTP(w, r)
			return
		}
		// NO upgrade-level kill-switch block (see the h3 branch above):
		// per-stream enforcement delivers the reason to clients.
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// NO subprotocol negotiation: echoing a purpose-built
			// subprotocol back answers "is this opentunnel?" in a single
			// packet — the cheapest active probe there is. Clients stopped
			// offering "otu1" long ago; offering none and confirming none
			// reads as an ordinary realtime channel.
			// Tunnel auth happens in-band after upgrade; rejecting on
			// Origin would only brick legit clients (and old relays must
			// keep accepting new ones mid-migration).
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "")
		stream := websocket.NetConn(r.Context(), conn, websocket.MessageBinary)
		handleSession(stream, opt, peerIP, ingress)
	}
	mux.HandleFunc(path, wsHandler)
	if path != protocol.LegacyWSPath {
		// Old clients still dial /ws: keep it mounted during migration.
		mux.HandleFunc(protocol.LegacyWSPath, wsHandler)
	}
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
	if !o.PanelDB.KnownPeer(tok) {
		// Unknown tokens are distinguishable now, and guessing gets
		// punished (guard strikes) instead of riding the pending path.
		// Purged devices re-register on the next dial and return to the
		// pending flow without further strikes.
		return protocol.StatusBadToken
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

// verifyHandshakeSig checks a v5 handshake's Ed25519 proof-of-possession
// against the SSH public key registered for the token ("ssh-ed25519 AAAA…"
// authorized-key format — the same key the ssh tier authorizes).
func verifyHandshakeSig(pubkeyAuthorized string, hs *protocol.Handshake) bool {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pubkeyAuthorized)))
	if err != nil {
		return false
	}
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	ed, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(ed, protocol.HandshakeMsg(hs.Token, hs.Salt), hs.Sig)
}

// handleSession authenticates one tunnel stream. peerIP is the resolved
// client address (behind a CDN front the TCP peer is the edge, not the
// client) and drives guard bans and the panel's device-IP view. ingress
// is the WithIngress marker ("" = public; IngressSSH = ssh transport).
func handleSession(stream net.Conn, opt Options, peerIP, ingress string) {
	defer stream.Close()
	metrics.SessionStarted()
	defer metrics.SessionEnded()

	_ = stream.SetDeadline(time.Now().Add(15 * time.Second))
	hs, err := protocol.ReadHandshake(stream)
	if err != nil {
		var st byte = protocol.StatusBadVersion
		if errors.Is(err, protocol.ErrBadToken) {
			st = protocol.StatusBadToken
		}
		opt.guard().Punish(peerIP)
		opt.logger().Printf("server: handshake rejected: %v", err)
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			_ = protocol.WriteHandshakeStatus(stream, protocol.ProtoVersion, st)
		}
		return
	}
	status := opt.verifyHandshakeToken(hs.Token)
	// v5 proof-of-possession (audit round three, N-1/N-2): a session
	// presenting a valid token must also prove possession of the device
	// key registered for it. Peers without a key on file (ancient
	// registrations) pass with a log line — all panel-era registrations
	// carry the key.
	if status == protocol.StatusOK && opt.PanelDB != nil {
		pub := opt.PanelDB.SSHPubKey(hs.Token)
		switch {
		case hs.Version >= protocol.ProtoVersion:
			if pub == "" {
				opt.logger().Printf("server: no registered key for %s — v5 signature not enforced this session", shortToken(hs.Token))
			} else if !verifyHandshakeSig(pub, hs) {
				opt.guard().Punish(peerIP)
				opt.PanelDB.RecordAlert("critical", "security",
					"handshake signature mismatch for device "+shortToken(hs.Token)+" — possible stolen token")
				opt.logger().Printf("server: v5 signature mismatch for %s", shortToken(hs.Token))
				_ = protocol.WriteHandshakeStatus(stream, hs.Version, protocol.StatusBadToken)
				return
			} else {
				// Sticky per-peer upgrade latch: from this moment a v4
				// hello for this token is a downgrade attempt.
				opt.PanelDB.MarkV5(hs.Token)
			}
		default: // v4 hello
			// Downgrade gate (audit round four): a token that has ever
			// authenticated with v5 must present v5 — v4 skips the
			// proof-of-possession check, so a harvested token alone used
			// to survive by downgrading. Keyless and never-v5 peers stay
			// admitted (migration window, auto-closing per identity).
			enforce := pub != ""
			if enforce && !opt.PanelDB.V5Seen(hs.Token) {
				// Not yet upgraded: only a passed enforcement date can
				// demand v5 now.
				enforce = !opt.RequireV5After.IsZero() && time.Now().After(opt.RequireV5After)
			}
			if enforce {
				opt.guard().Punish(peerIP)
				opt.PanelDB.RecordAlert("critical", "security",
					"v4 downgrade attempt for device "+shortToken(hs.Token)+" — possible stolen token (send v5)")
				opt.logger().Printf("server: v4 downgrade attempt for %s (v5 required)", shortToken(hs.Token))
				_ = protocol.WriteHandshakeStatus(stream, hs.Version, protocol.StatusBadToken)
				return
			}
		}
	}
	if err := protocol.WriteHandshakeStatus(stream, hs.Version, status); err != nil {
		return
	}
	if status != protocol.StatusOK {
		// Punish only genuine auth failures: pending/banned/expired peers
		// retry as part of normal flow and must not trip IP bans.
		if status == protocol.StatusBadToken {
			opt.guard().Punish(peerIP)
		}
		return
	}
	authTok := hs.Token

	// Loopback arrivals are the ssh tier's forward path, exempt from the
	// per-IP caps — bound them per identity instead.
	if isLoopbackIP(peerIP) {
		releaseTok := opt.guard().AcquireTokenSession(authTok)
		if releaseTok == nil {
			return // over the per-identity session cap
		}
		defer releaseTok()
	}

	// v5 carries the salt inside the handshake; v4 sends it right after.
	salt := hs.Salt
	if salt == nil {
		salt, err = protocol.ReadSalt(stream)
		if err != nil {
			return // silent close for malformed sessions
		}
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

	// Handshake phase over: lift the 15 s guard. Left armed, it would apply
	// to the whole session lifetime and kill every tunnel (and every long
	// download) 15 s after accept.
	_ = stream.SetDeadline(time.Time{})

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
	// Identity binding (pentest 2026-10-25): in panel mode the session's
	// accounting identity IS the token that authenticated the handshake —
	// it derived the AEAD keys. The in-band field stays on the wire for
	// protocol compatibility but can no longer move quota attribution,
	// last_ip or ban records onto another device (presenting a peer's
	// approved token used to ride that peer's quota).
	if opt.PanelDB != nil {
		clientToken = authTok
	}
	if clientToken == "" {
		clientToken = authTok // very old clients: handshake token doubles as panel token
	}
	if opt.PanelDB != nil {
		go opt.PanelDB.SetPeerIP(clientToken, peerIP)
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
	// For banned/kicked sessions, schedule a quick close: the client poll
	// notices within ~15 s and switches to notice mode locally, so a long
	// server-side wait only traps legitimately recovered devices (unban or
	// re-approve must take effect fast). 60 s backstops modified clients
	// that ignore the poll.
	if peerStatus == "banned" || peerStatus == "kicked" || peerStatus == "kicked-silent" {
		go func(s net.Conn, tok string) {
			time.Sleep(60 * time.Second)
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
		opt.serveMuxSession(sec, clientToken, peerStatus, peerReason, hs.Version, ingress)
	case protocol.UdpMarker:
		serveUDPStream(sec, opt, clientToken, peerStatus, ingress)
	default:
		relayTarget(mode[0], sec, opt, clientToken, peerStatus, peerReason, hs.Version, ingress)
	}
}

// relayTarget performs the classic single-target exchange on rw and pipes it
// to the dialed upstream until both directions finish. Used by legacy
// sessions and by every multiplexed stream. Traffic is recorded per-token;
// on ssh ingress the ssh-tier containment policy (sshtier.go) may cap the
// stream and its bytes count against the device's daily ssh budget.
func relayTarget(atyp byte, rw deadlineRW, opt Options, token, peerStatus, peerReason string, ver byte, ingress string) {
	defer rw.Close()
	// Global kill switch: block every new stream while suspended — except
	// the operator's allowlisted devices. The wire reason carries the
	// "down:" prefix and the admin's text, so the client renders the
	// traffic-down page with that exact message on every site.
	if opt.PanelDB != nil && opt.PanelDB.KillSwitch() && !opt.PanelDB.KillSwitchAllow(token) {
		_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusBlocked)
		reason := strings.TrimSpace(opt.PanelDB.KillSwitchReason())
		if reason == "" {
			reason = "shut down till further notice"
		}
		_ = protocol.WriteToken(rw, "blocked:down:"+reason)
		return
	}
	// ISP-level ban/kick handling
	if peerStatus == "banned" {
		_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusBlocked)
		_ = protocol.WriteToken(rw, "banned:"+peerReason)
		return
	}
	if peerStatus == "kicked" {
		_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusBlocked)
		_ = protocol.WriteToken(rw, "kicked:"+peerReason)
		return
	}
	if peerStatus == "kicked-silent" {
		_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusBlocked)
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
			_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusBlocked)
			// Send the rule (not just the domain): the client block page
			// states the reason, e.g. "ads category".
			why := opt.PanelDB.BlockWhy(name)
			if why == "" {
				why = "blocked"
			}
			_ = protocol.WriteToken(rw, "blocked:"+why)
			return
		}
	}
	// Record aggregated visited site (privacy: domain only, no URL, count
	// per peer). Off the hot path: a synchronous SQLite write per proxied
	// connection added latency to every page load; the bounded queue
	// drops under flood (monitoring data, not billing). Logs are sampled
	// so a busy relay does not fill journald.
	if opt.PanelDB != nil && token != "" && target.Domain != "" {
		recordVisitAsync(opt.PanelDB, token, target.Domain)
		if visitLogN.Add(1)%8 == 1 {
			opt.logger().Printf("visit %s -> %s", shortToken(token), target.Domain)
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !opt.AllowRestrictedTargets {
		dialer.Control = safeControl
	}
	upstream, err := dialer.Dial("tcp", target.HostPort())
	if err != nil {
		_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusDialFailed)
		opt.logger().Printf("server: dial %s failed: %v", target, err)
		return
	}
	defer upstream.Close()

	if err := protocol.WriteTargetResponse(rw, ver, protocol.StatusOK); err != nil {
		return
	}
	// No data-phase deadlines: the upstream dial already has a 10 s timeout,
	// and anything armed here would guillotine long transfers (large
	// downloads died ~10 s in). See TestRelaySurvivesSlowTransfer.
	_ = upstream.(*net.TCPConn).SetNoDelay(true)

	// 256 KiB copy buffers keep syscalls (and per-frame overhead) low on
	// high-BDP paths; both directions must finish before teardown.
	buf1 := make([]byte, 256*1024)
	buf2 := make([]byte, 256*1024)

	// Per-device bandwidth cap (QoS) + ssh-tier containment: one shared
	// token bucket paces both directions of this stream. 0 = unlimited.
	// On ssh ingress the policy adds the sustained ceiling and, once the
	// device's daily ssh budget is spent, the post-budget trickle rate —
	// bulk stops reading as a media feed without bricking browsing.
	pol := resolveStreamPolicy(opt, token, ingress)
	var dst1, dst2 io.Writer = upstream, rw
	if pol.limitBps > 0 {
		burst := int(pol.limitBps)
		if burst < len(buf1) {
			burst = len(buf1)
		}
		lim := rate.NewLimiter(rate.Limit(pol.limitBps), burst)
		dst1 = &limitedWriter{w: upstream, lim: lim}
		dst2 = &limitedWriter{w: rw, lim: lim}
		if ingress == IngressSSH {
			// Shape mimicry (segment.go): bulk on the ssh tier drains in
			// segment-sized bursts with jittered gaps — a streaming
			// player's fetch cadence, not a flat line-rate feed.
			sp := defaultSegmentParams()
			dst1 = newSegmentShaper(dst1, pol.limitBps, sp)
			dst2 = newSegmentShaper(dst2, pol.limitBps, sp)
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
	if pol.budgetBytes > 0 {
		sshBudgetAdd(token, n1+n2)
	}
}

// maxStreamsPerSession bounds concurrent smux streams on one tunnel session
// so an authenticated client cannot exhaust memory/fds by opening streams.
// Sized generously (clients spill over to fresh sessions well below this;
// see softCapStreams) — it is a backstop against runaway/malicious peers,
// not a throttle on legitimate bursts.
const maxStreamsPerSession = 512

// streamDropLog counts dropped streams so the saturation notice below is
// sampled instead of logging every drop during a burst storm.
var streamDropLog atomic.Uint64

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
// session; every stream inside carries one relayTarget exchange. ingress
// travels with each stream so the ssh-tier containment policy applies to
// the whole session's data (see sshtier.go).
func (o Options) serveMuxSession(sec io.ReadWriteCloser, token, peerStatus, peerReason string, ver byte, ingress string) {
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
			if streamDropLog.Add(1)%64 == 1 {
				o.logger().Printf("server: stream cap (%d) reached — dropping stream", maxStreamsPerSession)
			}
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
				serveUDPStream(s, o, token, peerStatus, ingress)
				return
			}
			if atyp[0] == protocol.CtrlMarker {
				serveCtrlStream(s, o)
				return
			}
			relayTarget(atyp[0], s, o, token, peerStatus, peerReason, ver, ingress)
		}(stream)
	}
}

var (
	replayOnce    sync.Once
	defaultReplay *protocol.ReplayCache
)

// visitLogN samples the per-connection visit log line (1-in-8).
var visitLogN atomic.Uint64

type visitRecorder interface {
	RecordVisit(token, domain string)
}

var (
	visitOnce sync.Once
	visitCh   chan visitEntry
)

type visitEntry struct {
	db            visitRecorder
	token, domain string
}

// recordVisitAsync queues a visit record onto a bounded worker (started
// on first use). Dropped under flood by design; at most one write in
// flight, so SQLite contention stays bounded.
func recordVisitAsync(db visitRecorder, token, domain string) {
	visitOnce.Do(func() {
		visitCh = make(chan visitEntry, 1024)
		go func() {
			for e := range visitCh {
				e.db.RecordVisit(e.token, e.domain)
			}
		}()
	})
	select {
	case visitCh <- visitEntry{db, token, domain}:
	default:
	}
}

// serveCtrlStream answers one in-band control request (status poll or
// health telemetry) on a mux stream. It exists because TLS-intercepting
// networks make the pinned HTTPS control plane unreachable BY DESIGN —
// inside the session the same data flows end-to-end encrypted, and the
// panel keeps hearing from those devices.
func serveCtrlStream(rw deadlineRW, opt Options) {
	_ = rw.SetDeadline(time.Now().Add(20 * time.Second))
	var req protocol.CtrlRequest
	if err := protocol.ReadCtrlMessage(rw, &req); err != nil {
		return
	}
	resp := protocol.CtrlResponse{}
	if opt.CurrentPin != nil {
		resp.Pin = opt.CurrentPin()
	}
	// Announced on every control response (status and health): the ssh
	// tier's dial target survives CDN fronting without config updates.
	resp.SSHHost = opt.SSHPublicHost
	defer func() { _ = protocol.WriteCtrlMessage(rw, resp) }()
	if opt.PanelDB == nil || req.Token == "" {
		return
	}
	switch req.Op {
	case "status":
		if !opt.PanelDB.KnownPeer(req.Token) {
			// Unknown/purged: the HTTPS contract answers 404, which the
			// client decodes as "" and re-registers. Mirror that in-band
			// so purged devices recover on every network.
			resp.OK = true
			resp.Status = ""
			return
		}
		status, kickReason, kickExpires, err := opt.PanelDB.CheckToken(req.Token)
		if err != nil {
			return
		}
		resp.OK = true
		resp.Status = status
		resp.KickReason = kickReason
		resp.KickExpires = kickExpires
		resp.BanReason = opt.PanelDB.BanReason(req.Token)
		opt.PanelDB.TouchPeer(req.Token)
	case "health":
		opt.PanelDB.RecordHealth(req.Token, req.Version, req.OS, req.Arch,
			req.CPUPct, req.MemPct, req.TempC, req.UptimeS,
			req.LatencyMs, req.JitterMs, req.ProbeLossPct)
		opt.PanelDB.TouchPeer(req.Token)
		resp.OK = true
	}
}

// shortToken returns an 8-char log prefix without assuming token length
// (tokens are client-chosen strings; slicing blindly could panic).
func shortToken(t string) string {
	if len(t) > 8 {
		return t[:8]
	}
	return t
}
