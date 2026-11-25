package panel

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/authority"
	"opentunnel/internal/panel/ui"
	"opentunnel/internal/panelproxy"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

var _ = time.Second // peers carry time.Time fields

type Handler struct {
	poolInfo           serverpool.Info
	poolChannelSupport bool
	poolAuthorityID    string
	poolID             string
	enrollmentLogin    bool
	enrollmentSlots    chan struct{}
	db                 *DB
	auth               *Auth
	autoApprove        bool
	geo                *GeoIP // optional; nil = no country resolution
	proxyProof         *panelproxy.Proof

	rlMu        sync.Mutex
	rlMap       map[string]*regLimit // per-IP rate-limit buckets (bucket|ip)
	rlSwept     time.Time            // last opportunistic expiry sweep
	keyMu       sync.Mutex           // serialize registration and admin key lifecycle hooks
	proofMu     sync.Mutex
	proofReplay *protocol.ReplayCache

	// OnApprove installs a device's SSH public key into the ssh tier's
	// authorized_keys when an admin approves it (nil = not configured).
	OnApprove func(token string)

	// OnRevoke removes a device's SSH key from authorized_keys when the
	// device is banned or deleted (1.0.1, N-12: revocation used to be a
	// lie — a banned device kept its key forever).
	OnRevoke     func(token string)
	sshReconcile func() error
}

type regLimit struct {
	count       int
	windowStart time.Time
}

const regLimitMax = 10 // registrations per IP per window
const regLimitWindow = time.Minute

func New(db *DB, auth *Auth, autoApprove bool) *Handler {
	return &Handler{db: db, auth: auth, autoApprove: autoApprove, rlMap: make(map[string]*regLimit), enrollmentSlots: make(chan struct{}, 4)}
}

// WithProxyProof enables authenticated relay metadata. A nil proof fails
// closed: forwarded headers remain untrusted and direct requests still work.
func (h *Handler) WithProxyProof(proof *panelproxy.Proof) *Handler {
	h.proxyProof = proof
	return h
}

// WithGeoIP attaches an offline GeoIP resolver (panel map / countries).
func (h *Handler) WithGeoIP(g *GeoIP) *Handler { h.geo = g; return h }

// WithApproveHook registers a callback fired after a device is approved.
func (h *Handler) WithApproveHook(fn func(token string)) *Handler { h.OnApprove = fn; return h }

// WithRevokeHook installs the N-12 revocation handler (ban/delete remove
// the device's key from authorized_keys).
func (h *Handler) WithRevokeHook(fn func(token string)) *Handler { h.OnRevoke = fn; return h }

// WithSSHReconciler applies durable desired/denied ownership after commit.
// Legacy token hooks are notifications, not revocation persistence or retries.
func (h *Handler) WithSSHReconciler(fn func() error) *Handler { h.sshReconcile = fn; return h }

// SSHKeyPath returns the stored SSH public key for a device token.
func (h *Handler) SSHKeyPath(token string) string {
	var pub string
	h.db.QueryRow(`SELECT COALESCE(ssh_pubkey,'') FROM peers WHERE token=?`, token).Scan(&pub)
	return pub
}

// rateAllowed enforces a per-IP windowed limit for the named bucket so no
// public endpoint can be hammered (registration spam, status-oracle
// enumeration, heartbeat floods). Keys are (bucket|ip).
func (h *Handler) rateAllowed(ip string, max int, window time.Duration, bucket string) bool {
	key := bucket + "|" + ip
	h.rlMu.Lock()
	defer h.rlMu.Unlock()
	now := time.Now()
	// Opportunistic sweep: without it, every IP that ever touched a
	// public endpoint stays in the map forever (a source-rotating
	// attacker grows panel memory unboundedly). Cheap because it runs at
	// most once per window.
	if now.Sub(h.rlSwept) > window {
		for k, v := range h.rlMap {
			if now.Sub(v.windowStart) > 10*window {
				delete(h.rlMap, k)
			}
		}
		h.rlSwept = now
	}
	r := h.rlMap[key]
	if r == nil || now.Sub(r.windowStart) > window {
		if r == nil && len(h.rlMap) >= 4096 {
			return false // expiry is not a memory bound; fail closed on new-source pressure
		}
		r = &regLimit{windowStart: now}
		h.rlMap[key] = r
	}
	r.count++
	return r.count <= max
}

// regAllowed enforces a per-IP registration rate limit so a banned device
// cannot hammer /api/token/request with fresh identities.
func (h *Handler) regAllowed(ip string) bool {
	return h.rateAllowed(ip, regLimitMax, regLimitWindow, "reg")
}

func (h *Handler) Mount(mux *http.ServeMux) {
	// The SPA handles login and first-run setup itself (calls the JSON APIs
	// below), so it is served publicly; every other admin route stays gated.
	// Once an admin exists the setup path is closed entirely: the SPA only
	// shows setup when setup-status says so, and the route itself bounces.
	mux.Handle("/admin/setup", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.auth.NeedsSetup() {
			h.dashboard(w, r)
			return
		}
		http.Redirect(w, r, "/admin/login", http.StatusFound)
	}))
	mux.Handle("/admin/login", http.HandlerFunc(h.dashboard))
	// Static SPA assets are public: the modulepreload/script tags in the
	// pre-login index.html must load with correct MIME types (an auth
	// redirect would serve HTML and the module would be rejected).
	mux.Handle("/admin/assets/", http.HandlerFunc(h.dashboard))
	mux.Handle("/admin/api/setup", http.HandlerFunc(h.apiSetup))
	mux.Handle("/admin/api/setup-status", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"needs_setup": h.auth.NeedsSetup()})
	}))
	mux.Handle("/admin/api/login", http.HandlerFunc(h.apiLogin))
	mux.Handle("/admin/logout", http.HandlerFunc(h.logout))
	// Standalone kill-switch console (plain HTML; the SPA bundle predates
	// the reason/allowlist fields and there is no rebuild toolchain).
	mux.Handle("/admin/killswitch", h.auth.RequireAuth(http.HandlerFunc(h.killswitchPage)))
	// Legacy sentinel bookmark: the integrated SPA owns this UI now.
	mux.Handle("/admin/sentinel", h.auth.RequireAuth(http.HandlerFunc(h.sentinelPage)))
	mux.Handle("/admin/ssh-keys", h.auth.RequireAuth(http.HandlerFunc(h.sshKeysPage)))
	mux.Handle("/admin/ssh-keys.js", h.auth.RequireAuth(http.HandlerFunc(h.sshKeysScript)))
	mux.Handle("/admin/api/ssh-keys", h.auth.RequireAuth(http.HandlerFunc(h.sshKeysAPI)))
	mux.Handle("/admin/enrollment-accounts", h.auth.RequireAuth(http.HandlerFunc(h.enrollmentAccountsPage)))
	mux.Handle("/admin/enrollment-accounts.js", h.auth.RequireAuth(http.HandlerFunc(h.enrollmentAccountsScript)))
	mux.Handle("/admin/api/enrollment-accounts", h.auth.RequireAuth(http.HandlerFunc(h.enrollmentAccountsAPI)))
	mux.Handle("/admin/api/peers", h.auth.RequireAuth(http.HandlerFunc(h.apiPeers)))
	mux.Handle("/admin/api/peers/", h.auth.RequireAuth(http.HandlerFunc(h.apiPeerAction)))
	mux.Handle("/admin/api/blocklist", h.auth.RequireAuth(http.HandlerFunc(h.apiBlocklist)))
	mux.Handle("/admin/api/categories", h.auth.RequireAuth(http.HandlerFunc(h.apiCategories)))
	mux.Handle("/admin/api/stats", h.auth.RequireAuth(http.HandlerFunc(h.apiStats)))
	mux.Handle("/admin/api/report", h.auth.RequireAuth(http.HandlerFunc(h.apiReport)))
	mux.Handle("/admin/api/visits", h.auth.RequireAuth(http.HandlerFunc(h.apiVisits)))
	mux.Handle("/admin/api/abuse", h.auth.RequireAuth(http.HandlerFunc(h.apiAbuse)))
	mux.Handle("/admin/api/events", h.auth.RequireAuth(http.HandlerFunc(h.apiEvents)))
	mux.Handle("/admin/api/settings", h.auth.RequireAuth(http.HandlerFunc(h.apiSettings)))
	mux.Handle("/admin/privacy", h.auth.RequireAuth(http.HandlerFunc(h.privacyPage)))
	mux.Handle("/admin/privacy.js", h.auth.RequireAuth(http.HandlerFunc(h.privacyScript)))
	mux.Handle("/admin/api/privacy", h.auth.RequireAuth(http.HandlerFunc(h.privacyAPI)))
	mux.Handle("/admin/api/alerts", h.auth.RequireAuth(http.HandlerFunc(h.apiAlerts)))
	mux.Handle("/admin/api/sentinel", h.auth.RequireAuth(http.HandlerFunc(h.apiSentinel)))
	mux.Handle("/admin/api/devices", h.auth.RequireAuth(http.HandlerFunc(h.apiDevices)))
	mux.Handle("/admin/api/server-health", h.auth.RequireAuth(http.HandlerFunc(h.apiServerHealth)))
	mux.Handle("/admin/api/hardening-status", h.auth.RequireAuth(http.HandlerFunc(h.hardeningStatusAPI)))
	mux.Handle("/admin/", h.auth.RequireAuth(http.HandlerFunc(h.dashboard)))

	// Public token api (no auth)
	mux.Handle("/api/token/request", http.HandlerFunc(h.tokenRequest))
	mux.Handle("/api/token/server-info", http.HandlerFunc(h.serverInfo))
	mux.Handle("/api/token/status", http.HandlerFunc(h.tokenStatus))
	mux.Handle("/api/token/heartbeat", http.HandlerFunc(h.tokenHeartbeat))
	mux.Handle("/api/token/health", http.HandlerFunc(h.tokenHealth))
}

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Mount(mux)
	return securityHeaders(h.authenticatePanelProxy(csrfOriginCheck(mux)))
}

// authenticatePanelProxy is the sole boundary that promotes relay headers to
// trusted request metadata. Header-free direct requests and authenticated
// authority context pass through. Any unverified relay field is rejected so a
// failed handoff cannot be demoted to the direct loopback identity.
func (h *Handler) authenticatePanelProxy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := panelproxy.FromRequest(r); !ok && panelproxy.HasForwardingMetadata(r) {
			if !trustedPanelProxy(r) || h.proxyProof == nil {
				http.Error(w, "panel proxy authentication failed", http.StatusForbidden)
				return
			}
			authenticated, err := h.proxyProof.AuthenticateStrict(r)
			if err != nil {
				status := http.StatusForbidden
				if errors.Is(err, panelproxy.ErrReplayCacheSaturated) {
					status = http.StatusServiceUnavailable
				} else if errors.Is(err, panelproxy.ErrBodyTooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, "panel proxy authentication failed", status)
				return
			}
			r = authenticated
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders applies the control-plane baseline (audit round three,
// O-1): no framing, no MIME sniffing, no referrer leakage, and a CSP that
// allows only same-origin scripts/styles (the SPA is fully embedded).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Admin API responses carry device tokens, allowlists and audit
		// data: browsers and disk caches must never keep them (1.0.1).
		if strings.HasPrefix(r.URL.Path, "/admin/api/") {
			h.Set("Cache-Control", "no-store")
		}
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'"+adminInlineScriptHashes+"; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self'; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// csrfOriginCheck rejects cross-origin state-changing requests. The admin
// session cookie is SameSite=Strict already; this is the second lock: a
// non-GET request whose Origin names a different site is refused before
// any handler runs. Requests without an Origin (curl, server-side calls)
// pass — they cannot be CSRF.
//
// Host comparison must survive the relay's reverse proxy, which rewrites
// r.Host to the loopback upstream (production incident 2026-10-28: the
// original comparison 403'd every browser login). The original host is used
// only after the panel authenticates the relay's complete forwarded tuple.
func csrfOriginCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" {
				hosts := []string{r.Host}
				if forwarded, ok := panelproxy.FromRequest(r); ok && forwarded.Host != "" {
					hosts = append(hosts, forwarded.Host)
				}
				ok := false
				for _, h := range hosts {
					if origin == "http://"+h || origin == "https://"+h {
						ok = true
						break
					}
				}
				if !ok {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) apiSetup(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if !h.auth.NeedsSetup() {
		http.Error(w, "already setup", http.StatusForbidden)
		return
	}
	// First-run gate: on a fresh deploy every unauthenticated visitor
	// would otherwise race the operator to own the panel. Setup requires
	// the operator's one-time bootstrap secret (env OTU_SETUP_TOKEN on
	// the panel process) — without it the door stays closed.
	want := os.Getenv("OTU_SETUP_TOKEN")
	if want == "" {
		http.Error(w, "setup locked: set OTU_SETUP_TOKEN on the panel process and restart to create the first admin", http.StatusForbidden)
		return
	}
	got := r.Header.Get("X-Setup-Token")
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		SetupTok string `json:"setup_token"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	defer clear(raw)
	if err != nil || serverpool.DecodeStrict(raw, &creds) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if got == "" {
		got = creds.SetupTok
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		// Slow failed gates down so the secret can't be brute-forced.
		if !h.rateAllowed(clientIP(r), 5, 15*time.Minute, "setup") {
			http.Error(w, "too many attempts", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "invalid setup token", http.StatusForbidden)
		return
	}
	if len(creds.Username) < 3 || len(creds.Password) < 8 {
		http.Error(w, "username min 3, password min 8", 400)
		return
	}
	if err := h.auth.CreateAdmin(creds.Username, creds.Password); err != nil {
		http.Error(w, "setup failed (maybe already done)", 400)
		return
	}
	sid := h.auth.CreateSession(creds.Username)
	if sid == "" {
		http.Error(w, "session service unavailable", 503)
		return
	}
	h.auth.SetSessionCookie(w, sid)
	h.db.RecordEvent("setup", "first admin created ("+creds.Username+")")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) apiLogin(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	ip := clientIP(r)
	// 4 KB is generous for two strings; the relay proxies this endpoint
	// publicly, and an unbounded body let an unauthenticated caller make
	// the panel buffer attacker-sized payloads (1.0.1).
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	raw, err := io.ReadAll(r.Body)
	defer clear(raw)
	if err != nil || serverpool.DecodeStrict(raw, &creds) != nil || len(creds.Username) < 3 || len(creds.Username) > 64 || len(creds.Password) > 72 {
		http.Error(w, "invalid login request", 400)
		return
	}
	attempt, admitted := h.auth.beginLogin(ip)
	if !admitted {
		http.Error(w, "too many failed or outstanding login attempts — try again later", 429)
		return
	}
	defer attempt.finish(false, false)
	ok, err := h.auth.Login(creds.Username, creds.Password)
	if err != nil {
		if errors.Is(err, ErrAuthenticationBusy) {
			http.Error(w, "authentication busy — retry later", 429)
			return
		}
		http.Error(w, "authentication temporarily unavailable", 503)
		return
	}
	if !ok {
		attempt.finish(false, true)
		if h.auth.LoginLocked(ip) {
			// Visible, not silent: a lockout flood is an attack signal the
			// admin should see on the panel, not discover afterwards.
			h.db.RecordAlert("warning", "panel", "login lockout triggered for IP "+ip)
		}
		http.Error(w, "invalid credentials", 401)
		return
	}
	attempt.finish(true, false)
	sid := h.auth.CreateSession(creds.Username)
	if sid == "" {
		http.Error(w, "session capacity reached; retry later", 429)
		return
	}
	if sid == "" {
		http.Error(w, "session service unavailable", 503)
		return
	}
	h.auth.SetSessionCookie(w, sid)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("panel_session"); err == nil {
		h.auth.DestroySession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "panel_session", MaxAge: -1, Path: "/admin"})
	http.Redirect(w, r, "/admin/login", 302)
}

// clientIP resolves the caller's IP from authenticated relay/authority
// metadata. Untrusted or unproved headers never affect rate-limit identity.
// Direct requests (tests, emergency panel access on loopback) use RemoteAddr.
func clientIP(r *http.Request) string {
	if forwarded, ok := panelproxy.FromRequest(r); ok && net.ParseIP(forwarded.ClientIP) != nil {
		return forwarded.ClientIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func trustedPanelProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	// Serve the embedded SPA. Real files under dist/ are served as-is;
	// any other /admin/* path falls back to index.html (client routing).
	p := strings.TrimPrefix(r.URL.Path, "/admin/")
	if p != "" {
		if f, err := ui.Dist.Open("dist/" + p); err == nil {
			f.Close()
			http.ServeFileFS(w, r, ui.Dist, "dist/"+p)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, ui.Dist, "dist/index.html")
}

func (h *Handler) apiPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := h.db.PeersChecked(r.Context())
	if err == nil && h.geo != nil {
		for i := range peers {
			if peers[i].LastIP != "" {
				peers[i].Country = h.geo.CountryName(peers[i].LastIP)
			}
		}
	}
	writeDiagnosticJSON(w, peers, err, "peer inventory unavailable")
}

// shortTokens abbreviates a token list for event log text.
func shortTokens(toks []string) []string {
	out := make([]string, 0, len(toks))
	for _, t := range toks {
		if len(t) > 8 {
			t = t[:8]
		}
		out = append(out, t)
	}
	return out
}

// validTokenCharset reports whether a token is safe to use in URL paths
// and DB keys. Tokens are opaque credentials minted by clients
// (base64url of 32 random bytes) — anything containing a slash, brace or
// other structural character is not a token, it is an injection attempt
// (audit round three, H-1: a registered token of "12345678/approve" made
// the panel's ban-click execute approve via the path-split router).
var tokenCharset = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func validTokenCharset(s string) bool { return tokenCharset.MatchString(s) }

// requirePOST answers 405 for anything but POST on endpoints whose
// action semantics are POST-native (registration, peer actions): a GET
// reachable action path multiplies CSRF/delivery vectors for no benefit.
func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (h *Handler) apiPeerAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/api/peers/"), "/")
	if len(parts) != 2 {
		http.Error(w, "bad request", 400)
		return
	}
	token, action := parts[0], parts[1]
	if !validTokenCharset(token) {
		// Poisoned peer row (pre-fix registration): refuse to act on it
		// through the URL router at all — the admin action cannot be
		// redirected by a crafted token.
		http.Error(w, "invalid token", 400)
		return
	}
	if action != "limits" || r.Method != http.MethodGet {
		if !requirePOST(w, r) {
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	h.keyMu.Lock()
	defer h.keyMu.Unlock()
	short := token
	if len(short) > 8 {
		short = short[:8]
	}
	switch action {
	case "rekey":
		var req struct {
			PublicKey string `json:"ssh_pubkey"`
			Expected  string `json:"expected_ssh_pubkey"`
			Confirm   bool   `json:"confirm"`
		}
		if decodePeerMutation(r, &req, false) != nil || !req.Confirm {
			http.Error(w, "verify the new public key out of band and explicitly confirm replacement", http.StatusBadRequest)
			return
		}
		pub, ok := CanonicalSSHPubKey(req.PublicKey)
		if !ok {
			http.Error(w, "ssh_pubkey must be one ed25519 public key", http.StatusBadRequest)
			return
		}
		if _, err := h.db.RekeyPeer(token, req.Expected, pub); err != nil {
			http.Error(w, "key replacement unavailable or identity changed; nothing replaced", 409)
			return
		}
		// Never auto-approve a rekey, including during auto-accept windows.
	case "approve":
		if decodePeerMutation(r, &struct{}{}, true) != nil {
			http.Error(w, "invalid approval request", 400)
			return
		}
		if err := h.db.PeerStateAction(token, "approve", "", ""); err != nil {
			http.Error(w, "approval unavailable", http.StatusServiceUnavailable)
			return
		}
		h.db.RecordAlert("info", "nac", "device "+short+" approved for network access")
		if h.OnApprove != nil {
			h.OnApprove(token)
		}
	case "kick":
		var req struct {
			Reason string `json:"reason"`
		}
		if err := decodePeerMutation(r, &req, true); err != nil {
			http.Error(w, "invalid kick request", 400)
			return
		}
		if len(req.Reason) > 500 {
			http.Error(w, "reason too long", 400)
			return
		}
		if err := h.db.PeerStateAction(token, "kick", req.Reason, ""); err != nil {
			http.Error(w, "kick unavailable or identity not approved", 409)
			return
		}
		h.db.RecordAlert("warning", "nac", "device "+short+" kicked: "+trimReason(req.Reason))
	case "ban":
		var req struct {
			Reason   string `json:"reason"`
			Duration string `json:"duration"`
		}
		if err := decodePeerMutation(r, &req, true); err != nil {
			http.Error(w, "invalid ban request", 400)
			return
		}
		if len(req.Reason) > 500 || len(req.Duration) > 64 {
			http.Error(w, "ban fields too long", 400)
			return
		}
		if err := h.db.PeerStateAction(token, "ban", req.Reason, req.Duration); err != nil {
			http.Error(w, "ban unavailable", http.StatusServiceUnavailable)
			return
		}
		if h.OnRevoke != nil {
			h.OnRevoke(token) // N-12: remove the ssh-tier key while the row still exists
		}
		h.db.RecordAlert("critical", "security", "device "+short+" BANNED (fingerprint + key): "+trimReason(req.Reason))
	case "unban":
		if decodePeerMutation(r, &struct{}{}, true) != nil {
			http.Error(w, "invalid unban request", 400)
			return
		}
		if err := h.db.PeerStateAction(token, "unban", "", ""); err != nil {
			http.Error(w, "unban unavailable", 503)
			return
		}
		h.db.RecordAlert("info", "security", "device "+short+" unbanned — pending re-approval")
	case "delete":
		if decodePeerMutation(r, &struct{}{}, true) != nil {
			http.Error(w, "invalid delete request", 400)
			return
		}
		if err := h.db.PeerStateAction(token, "delete", "", ""); err != nil {
			http.Error(w, "delete unavailable", 503)
			return
		}
	case "reset":
		if decodePeerMutation(r, &struct{}{}, true) != nil {
			http.Error(w, "invalid reset request", 400)
			return
		}
		if err := h.db.PeerStateAction(token, "reset", "", ""); err != nil {
			http.Error(w, "usage reset unavailable", 503)
			return
		}
	case "expire":
		if decodePeerMutation(r, &struct{}{}, true) != nil {
			http.Error(w, "invalid expiry request", 400)
			return
		}
		if err := h.db.PeerStateAction(token, "expire", "", ""); err != nil {
			http.Error(w, "expiry unavailable", 503)
			return
		}
		if h.OnRevoke != nil {
			h.OnRevoke(token)
		}
	case "limits":
		if r.Method == "GET" {
			var sched string
			var maxBps, quota int64
			if err := h.db.QueryRowContext(r.Context(), `SELECT COALESCE(schedule,''), COALESCE(max_bps,0), COALESCE(quota_bytes,0) FROM peers WHERE token=?`, token).Scan(&sched, &maxBps, &quota); err != nil {
				http.Error(w, "limits unavailable", 503)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"schedule": sched, "max_bps": maxBps, "quota_bytes": quota})
			return
		}
		var req struct {
			Schedule   string `json:"schedule"`
			MaxBps     int64  `json:"max_bps"`
			QuotaBytes int64  `json:"quota_bytes"`
		}
		if err := decodePeerMutation(r, &req, false); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		if !ValidateSchedule(req.Schedule) {
			http.Error(w, "invalid schedule (e.g. \"Mon-Fri 0800-1800\")", 400)
			return
		}
		if req.MaxBps < 0 || req.QuotaBytes < 0 {
			http.Error(w, "limits must be >= 0", 400)
			return
		}
		if err := h.db.SetPeerLimitsChecked(token, req.Schedule, req.MaxBps, req.QuotaBytes); err != nil {
			http.Error(w, "limits update unavailable; nothing changed", 503)
			return
		}
	default:
		http.Error(w, "unknown device action", http.StatusBadRequest)
		return
	}
	if h.sshReconcile != nil {
		if err := h.sshReconcile(); err != nil {
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"ok":true,"ssh_reconcile_pending":true}`))
			return // admission committed; never claim the SSH file is applied
		}
	}
	w.Write([]byte(`{"ok":true}`))
}

func decodePeerMutation(r *http.Request, dst any, allowEmpty bool) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 && allowEmpty {
		return nil
	}
	return serverpool.DecodeStrict(raw, dst)
}

func (h *Handler) apiBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, err := h.db.QueryContext(r.Context(), `SELECT domain,COALESCE(reason,'') FROM blocklist ORDER BY domain LIMIT ?`, maxBlockRules+1)
		if err != nil {
			http.Error(w, "blocklist unavailable", 503)
			return
		}
		defer rows.Close()
		list := []map[string]string{}
		for rows.Next() {
			var d, rsn string
			if err := rows.Scan(&d, &rsn); err != nil {
				http.Error(w, "blocklist unavailable", 503)
				return
			}
			list = append(list, map[string]string{"domain": d, "reason": rsn})
			if len(list) > maxBlockRules {
				http.Error(w, "blocklist exceeds capacity", 503)
				return
			}
		}
		if rows.Err() != nil {
			http.Error(w, "blocklist unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(list)
		return
	}
	var req struct {
		Domain       string `json:"domain"`
		Reason       string `json:"reason"`
		Clear        bool   `json:"clear"`
		ConfirmClear bool   `json:"confirm_clear,omitempty"`
	}
	if r.Method != "POST" && r.Method != "DELETE" {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil || serverpool.DecodeStrict(raw, &req) != nil {
		http.Error(w, "invalid blocklist request", 400)
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if len(req.Reason) > 500 || (req.Clear && (r.Method != "DELETE" || !req.ConfirmClear || req.Domain != "")) || (!req.Clear && (!validBlockDomain(req.Domain) || req.ConfirmClear)) {
		http.Error(w, "domain required; clearing all rules requires clear=true and confirm_clear=true", 400)
		return
	}
	if err := h.db.BlocklistAction(r.Context(), r.Method, req.Domain, req.Reason, req.Clear); err != nil {
		http.Error(w, "blocklist update unavailable; nothing changed", 503)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.StatsChecked(r.Context(), h.geo)
	writeDiagnosticJSON(w, stats, err, "statistics unavailable")
}

func (h *Handler) apiReport(w http.ResponseWriter, r *http.Request) {
	report, err := h.db.WeeklyReportChecked(r.Context())
	writeDiagnosticJSON(w, report, err, "traffic report unavailable")
}

func (h *Handler) apiVisits(w http.ResponseWriter, r *http.Request) {
	// Aggregated for privacy: domain -> total hits, no per-peer URLs, no IP
	visits, err := h.db.VisitsChecked(r.Context())
	writeDiagnosticJSON(w, visits, err, "visit summary unavailable")
}

func (h *Handler) apiAbuse(w http.ResponseWriter, r *http.Request) {
	// Live counters only (1.0.1). The old hardcoded note advertised guard
	// limits that were never wired here, and it disclosed operator
	// tradecraft (decoy maintenance) in an API response — audit round
	// four flagged it as four rounds overdue.
	abuse, err := h.db.AbuseChecked(r.Context())
	writeDiagnosticJSON(w, abuse, err, "abuse diagnostics unavailable")
}

func (h *Handler) apiEvents(w http.ResponseWriter, r *http.Request) {
	events, err := h.db.RecentEventsChecked(r.Context(), 50)
	writeDiagnosticJSON(w, events, err, "event feed unavailable")
}

// apiSentinel (v1.1.0): visibility and control for the proactive
// detectors. GET returns the response mode and recent findings; POST sets
// the mode (off | alert | respond). The relay-side detectors pick the new
// mode up within ~15s (their settings cache).
func (h *Handler) apiSentinel(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sentinel, err := h.db.SentinelChecked(r.Context())
		writeDiagnosticJSON(w, sentinel, err, "sentinel diagnostics unavailable")
		return
	}
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if readErr != nil || serverpool.DecodeStrict(raw, &req) != nil {
		http.Error(w, "mode required", 400)
		return
	}
	mode := strings.TrimSpace(req.Mode)
	switch mode {
	case "off", "alert", "respond":
	default:
		http.Error(w, "mode must be off | alert | respond", 400)
		return
	}
	if err := h.db.SetSettings(map[string]string{"sentinel_mode": mode}); err != nil {
		http.Error(w, "sentinel policy unavailable; nothing changed", 503)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"mode": mode})
}

func (h *Handler) legacySettings(w http.ResponseWriter, r *http.Request) {
	h.apiSettings(w, r) // compatibility wrapper shares strict atomic audited semantics
}

func (h *Handler) apiCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		categories, err := h.db.CategoriesChecked(r.Context())
		if err != nil {
			http.Error(w, "filtering categories unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(categories)
		return
	}
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Category string `json:"category"`
		Enabled  *bool  `json:"enabled"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil || serverpool.DecodeStrict(raw, &req) != nil || req.Enabled == nil {
		http.Error(w, "unknown category", 400)
		return
	}
	if _, ok := categoryLists[req.Category]; !ok {
		http.Error(w, "unknown category", 400)
		return
	}
	if err := h.db.SetCategoryEnabledChecked(r.Context(), req.Category, *req.Enabled); err != nil {
		http.Error(w, "category update unavailable; nothing changed", 503)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) tokenRequest(w http.ResponseWriter, r *http.Request) {
	if h.poolID != "" {
		h.enrollPool(w, r)
		return
	}
	if !requirePOST(w, r) {
		return
	}
	if !h.regAllowed(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10) // 16 KB is plenty for registration
	var req registrationRequest
	raw, readErr := io.ReadAll(r.Body)
	if readErr != nil || serverpool.DecodeStrict(raw, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.Fingerprint == "" {
		http.Error(w, "token and fingerprint required", 400)
		return
	}
	if len(req.Token) < 16 || len(req.Token) > 1024 {
		http.Error(w, "token must be 16-1024 chars", 400)
		return
	}
	// Charset gate (H-1): a token carrying "/" or other path-structural
	// characters could not be a client-minted credential, and letting it
	// into the store turns every admin action URL into an injection
	// surface. First line of defense; the action handler re-checks.
	if !validTokenCharset(req.Token) {
		http.Error(w, "invalid token characters", 400)
		return
	}
	// Bounded fields: a hostile registrant must not be able to stuff
	// multi-megabyte strings into the DB / alert feed.
	if len(req.DeviceName) > 64 || len(req.Fingerprint) > 128 || len(req.SSHPubKey) > 2048 {
		http.Error(w, "field too long", 400)
		return
	}
	// SSH key validation (1.0.1): the old length-only check let a
	// registrant smuggle newlines — once approved, the verbatim append
	// installed extra UNRESTRICTED keys into root-served authorized_keys
	// (audit round four, N-11 chain). Store the canonical single-line
	// ed25519 form or refuse.
	req.SSHPubKey = strings.TrimSpace(req.SSHPubKey)
	if req.SSHPubKey == "" {
		http.Error(w, "new enrollment requires an Ed25519 public key", 400)
		return
	}
	if req.SSHPubKey != "" {
		canon, cok := CanonicalSSHPubKey(req.SSHPubKey)
		if !cok {
			http.Error(w, "ssh_pubkey must be a single ed25519 key line", 400)
			return
		}
		req.SSHPubKey = canon
	}
	h.keyMu.Lock()
	defer h.keyMu.Unlock()
	status, changed, created, err := h.db.registerBootstrap(r.Context(), req, h.autoApprove)
	if errors.Is(err, errRegistrationConflict) {
		if h.db.throttleKV("key-conflict|"+req.Token, time.Hour) {
			h.db.RecordAlert("warning", "security", "conflicting bootstrap identity for device "+shortPK(req.Token)+"; stored identity preserved")
		}
		http.Error(w, "identity conflict: an administrator must verify and replace the public key", 409)
		return
	}
	if errors.Is(err, errRegistrationDenied) {
		http.Error(w, "identity not eligible for bootstrap enrollment", 403)
		return
	}
	if err != nil {
		http.Error(w, "registration unavailable; no partial enrollment or approval", 503)
		return
	}
	if created || status == "pending" {
		h.db.SetPeerIP(req.Token, clientIP(r))
	}
	if created {
		h.db.RecordAlert("info", "nac", "new device "+req.DeviceName+" registered — status: "+status)
	}
	if changed && status == "approved" && h.OnApprove != nil {
		h.OnApprove(req.Token)
	}
	if changed && h.sshReconcile != nil {
		if err := h.sshReconcile(); err != nil {
			w.WriteHeader(http.StatusAccepted)
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func (h *Handler) tokenStatus(w http.ResponseWriter, r *http.Request) {
	if h.poolID != "" {
		h.poolTokenStatus(w, r)
		return
	}
	// Status is how devices learn their admission state — but an
	// unauthenticated oracle that answers at line speed also enumerates
	// tokens and leaks ban/kick reasons. 60 queries per IP per minute is
	// ~4x a poll cadence and far below enumeration speed.
	if !h.rateAllowed(clientIP(r), 60, time.Minute, "status") {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	// Token rides the query (legacy GET clients) or the JSON body (v0.9.22+
	// POST). The body form exists so the credential never appears in an
	// interceptable URL line.
	token := r.URL.Query().Get("token")
	if token == "" {
		var req struct {
			Token string `json:"token"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<12)
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			token = req.Token
		}
	}
	p, err := h.db.AccessPolicy(token)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", 404)
		return
	}
	if err != nil {
		http.Error(w, "status unavailable", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"status": p.Status, "kick_reason": p.Reason, "ban_reason": p.Reason, "kick_expires": p.Expires,
	})
}

func (h *Handler) tokenHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	// Heartbeats are one tiny token per minute per device; anything bigger
	// or faster is a flood (a 64MB JSON POST used to be accepted here).
	if !h.rateAllowed(clientIP(r), 30, time.Minute, "hb") {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if serverpool.DecodeStrict(body, &req) != nil || !validTokenCharset(req.Token) {
		http.Error(w, "bad request", 400)
		return
	}
	p, policyErr := h.db.AccessPolicy(req.Token)
	if policyErr != nil {
		http.Error(w, "device status unavailable", 503)
		return
	}
	if !h.verifyKeyHTTPProof(r, p.PublicKey, body) {
		http.Error(w, "device proof required", 403)
		return
	}
	if _, err := h.db.controlAuthenticated(r.Context(), authority.ControlRequest{Token: req.Token, Generation: p.Generation, PublicKey: p.PublicKey, Request: protocol.CtrlRequest{Op: "status"}}, false, false); err != nil {
		http.Error(w, "heartbeat unavailable; no liveness changed", 503)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

// tokenHealth ingests client telemetry (device posture for NAC/inventory).
// Public but rate-limited per IP; unknown tokens are ignored.
func (h *Handler) tokenHealth(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if !h.rateAllowed(clientIP(r), 120, time.Minute, "health") {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10) // telemetry is tiny
	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		http.Error(w, "bad request", 400)
		return
	}
	var req struct {
		Token                 string  `json:"token"`
		Version               string  `json:"version"`
		OS                    string  `json:"os"`
		Arch                  string  `json:"arch"`
		CPUPct                float64 `json:"cpu_pct"`
		MemPct                float64 `json:"mem_pct"`
		TempC                 float64 `json:"temp_c"`
		UptimeS               int64   `json:"uptime_s"`
		LatencyMs             float64 `json:"latency_ms"`
		JitterMs              float64 `json:"jitter_ms"`
		ProbeLossPct          float64 `json:"probe_loss_pct"`
		UpdateChannel         string  `json:"update_channel,omitempty"`
		UpdateState           string  `json:"update_state,omitempty"`
		ChannelAuthentication bool    `json:"channel_authentication,omitempty"`
	}
	if err := serverpool.DecodeStrict(body, &req); err != nil || !validTokenCharset(req.Token) {
		http.Error(w, "bad request", 400)
		return
	}
	// Bounded telemetry strings (token length is enforced at registration).
	if len(req.Version) > 64 || len(req.OS) > 64 || len(req.Arch) > 32 {
		http.Error(w, "field too long", 400)
		return
	}
	p, policyErr := h.db.AccessPolicy(req.Token)
	if policyErr != nil {
		http.Error(w, "device status unavailable", 503)
		return
	}
	if !h.verifyKeyHTTPProof(r, p.PublicKey, body) {
		http.Error(w, "device proof required", 403)
		return
	}
	if _, err := h.db.controlAuthenticated(r.Context(), authority.ControlRequest{Token: req.Token, Generation: p.Generation, PublicKey: p.PublicKey, Request: protocol.CtrlRequest{Op: "health", Version: req.Version, OS: req.OS, Arch: req.Arch, CPUPct: req.CPUPct, MemPct: req.MemPct, TempC: req.TempC, UptimeS: req.UptimeS, LatencyMs: req.LatencyMs, JitterMs: req.JitterMs, ProbeLossPct: req.ProbeLossPct, UpdateChannel: req.UpdateChannel, UpdateState: req.UpdateState, ChannelAuthentication: req.ChannelAuthentication}}, false, false); err != nil {
		http.Error(w, "telemetry unavailable or identity no longer admitted", 503)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			ID  int64 `json:"id"`
			Ack bool  `json:"ack"`
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
		if err != nil || serverpool.DecodeStrict(raw, &req) != nil || req.ID < 1 || !req.Ack {
			http.Error(w, "bad request", 400)
			return
		}
		if err := h.db.AckAlertChecked(r.Context(), req.ID); err != nil {
			http.Error(w, "alert acknowledgement unavailable; nothing changed", 503)
			return
		}
		w.Write([]byte(`{"ok":true}`))
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", 405)
		return
	}
	alerts, err := h.db.AlertsSnapshotChecked(r.Context(), 60)
	writeDiagnosticJSON(w, alerts, err, "alerts unavailable")
}

// apiDevices returns the device inventory: peers joined with telemetry.
func (h *Handler) apiDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.db.AllHealthChecked(r.Context())
	if err == nil && h.geo != nil {
		for i := range devices {
			if devices[i].LastIP != "" {
				devices[i].Country = h.geo.CountryName(devices[i].LastIP)
			}
		}
	}
	writeDiagnosticJSON(w, devices, err, "device inventory unavailable")
}
