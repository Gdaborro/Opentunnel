package panel

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/panel/ui"
)

var _ = time.Second // peers carry time.Time fields

type Handler struct {
	db          *DB
	auth        *Auth
	autoApprove bool
	geo         *GeoIP // optional; nil = no country resolution

	rlMu    sync.Mutex
	rlMap   map[string]*regLimit // per-IP rate-limit buckets (bucket|ip)
	rlSwept time.Time            // last opportunistic expiry sweep

	// OnApprove installs a device's SSH public key into the ssh tier's
	// authorized_keys when an admin approves it (nil = not configured).
	OnApprove func(token string)
}

type regLimit struct {
	count       int
	windowStart time.Time
}

const regLimitMax = 10 // registrations per IP per window
const regLimitWindow = time.Minute

func New(db *DB, auth *Auth, autoApprove bool) *Handler {
	return &Handler{db: db, auth: auth, autoApprove: autoApprove, rlMap: make(map[string]*regLimit)}
}

// WithGeoIP attaches an offline GeoIP resolver (panel map / countries).
func (h *Handler) WithGeoIP(g *GeoIP) *Handler { h.geo = g; return h }

// WithApproveHook registers a callback fired after a device is approved.
func (h *Handler) WithApproveHook(fn func(token string)) *Handler { h.OnApprove = fn; return h }

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
	mux.Handle("/admin/api/alerts", h.auth.RequireAuth(http.HandlerFunc(h.apiAlerts)))
	mux.Handle("/admin/api/devices", h.auth.RequireAuth(http.HandlerFunc(h.apiDevices)))
	mux.Handle("/admin/api/server-health", h.auth.RequireAuth(http.HandlerFunc(h.apiServerHealth)))
	mux.Handle("/admin/", h.auth.RequireAuth(http.HandlerFunc(h.dashboard)))

	// Public token api (no auth)
	mux.Handle("/api/token/request", http.HandlerFunc(h.tokenRequest))
	mux.Handle("/api/token/status", http.HandlerFunc(h.tokenStatus))
	mux.Handle("/api/token/heartbeat", http.HandlerFunc(h.tokenHeartbeat))
	mux.Handle("/api/token/health", http.HandlerFunc(h.tokenHealth))
}

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Mount(mux)
	return securityHeaders(csrfOriginCheck(mux))
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
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
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
// original comparison 403'd every browser login). The relay stamps the
// original, browser-facing host in X-Otu-Original-Host before rewriting —
// overwritten relay-side so the value is unspoofable from outside.
func csrfOriginCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" {
				hosts := []string{r.Host}
				if fh := r.Header.Get("X-Otu-Original-Host"); fh != "" {
					hosts = append(hosts, fh)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&creds); err != nil {
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
	h.auth.SetSessionCookie(w, sid)
	h.db.RecordEvent("setup", "first admin created ("+creds.Username+")")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) apiLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.auth.LoginLocked(ip) {
		http.Error(w, "too many failed attempts — try again later", http.StatusTooManyRequests)
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&creds)
	ok, _ := h.auth.Login(creds.Username, creds.Password)
	if !ok {
		h.auth.RecordLoginFail(ip)
		if h.auth.LoginLocked(ip) {
			// Visible, not silent: a lockout flood is an attack signal the
			// admin should see on the panel, not discover afterwards.
			h.db.RecordAlert("warning", "panel", "login lockout triggered for IP "+ip)
		}
		http.Error(w, "invalid credentials", 401)
		return
	}
	h.auth.ClearLoginFail(ip)
	sid := h.auth.CreateSession(creds.Username)
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

// clientIP resolves the caller's IP. The relay's reverse proxy stamps
// X-Otu-Client-IP on every proxied request (an unspoofable view — it
// overwrites anything the outside sent, and includes the CDN-resolved
// address when the relay is fronted). Direct requests (tests, emergency
// panel access on loopback) fall back to RemoteAddr.
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Otu-Client-IP"); net.ParseIP(v) != nil {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
	rows, err := h.db.Query(`SELECT token,fingerprint,device_name,status,created_at,last_seen,bytes_up,bytes_down,kick_reason,ban_reason,COALESCE(last_ip,'') FROM peers ORDER BY last_seen DESC`)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	peers := []Peer{}
	for rows.Next() {
		var p Peer
		var kickReason, banReason sql.NullString
		if err := rows.Scan(&p.Token, &p.Fingerprint, &p.DeviceName, &p.Status, &p.CreatedAt, &p.LastSeen,
			&p.BytesUp, &p.BytesDown, &kickReason, &banReason, &p.LastIP); err != nil {
			// Row skipped rather than aborting the whole list
			continue
		}
		p.KickReason = kickReason.String
		p.BanReason = banReason.String
		if h.geo != nil && p.LastIP != "" {
			p.Country = h.geo.CountryName(p.LastIP)
		}
		peers = append(peers, p)
	}
	json.NewEncoder(w).Encode(peers)
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
	if !requirePOST(w, r) {
		return
	}
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
	short := token
	if len(short) > 8 {
		short = short[:8]
	}
	switch action {
	case "approve":
		h.db.Exec(`UPDATE peers SET status='approved', last_seen=datetime('now') WHERE token=?`, token)
		h.db.RecordEvent("approve", short+" approved")
		h.db.RecordAlert("info", "nac", "device "+short+" approved for network access")
		if h.OnApprove != nil {
			h.OnApprove(token)
		}
	case "kick":
		var req struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		h.db.Exec(`UPDATE peers SET status='kicked', kick_reason=?, kick_expires=datetime('now','+10 minutes') WHERE token=?`, req.Reason, token)
		h.db.RecordEvent("kick", short+" kicked: "+req.Reason)
		h.db.RecordAlert("warning", "nac", "device "+short+" kicked: "+trimReason(req.Reason))
	case "ban":
		var req struct {
			Reason   string `json:"reason"`
			Duration string `json:"duration"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		h.db.Exec(`UPDATE peers SET status='banned', ban_reason=?, ban_duration=? WHERE token=?`, req.Reason, req.Duration, token)
		h.db.BanIdentity(token, req.Reason)
		h.db.RecordEvent("ban", short+" banned: "+req.Reason)
		h.db.RecordAlert("critical", "security", "device "+short+" BANNED (fingerprint + key): "+trimReason(req.Reason))
	case "unban":
		h.db.UnbanIdentity(token)
		h.db.Exec(`UPDATE peers SET status='pending', ban_reason=NULL, ban_duration=NULL WHERE token=?`, token)
		h.db.RecordEvent("unban", short+" unbanned (needs re-approval)")
		h.db.RecordAlert("info", "security", "device "+short+" unbanned — pending re-approval")
	case "delete":
		h.db.UnbanIdentity(token)
		h.db.Exec(`DELETE FROM peers WHERE token=?`, token)
		h.db.Exec(`DELETE FROM daily_usage WHERE token=?`, token)
		h.db.Exec(`DELETE FROM visits WHERE token=?`, token)
		h.db.RecordEvent("delete", short+" deleted")
	case "reset":
		h.db.Exec(`UPDATE peers SET bytes_up=0, bytes_down=0 WHERE token=?`, token)
		h.db.Exec(`DELETE FROM daily_usage WHERE token=?`, token)
	case "expire":
		h.db.Exec(`UPDATE peers SET status='expired' WHERE token=?`, token)
	case "limits":
		if r.Method == "GET" {
			var sched string
			var maxBps, quota int64
			h.db.QueryRow(`SELECT COALESCE(schedule,''), COALESCE(max_bps,0), COALESCE(quota_bytes,0) FROM peers WHERE token=?`, token).Scan(&sched, &maxBps, &quota)
			json.NewEncoder(w).Encode(map[string]any{"schedule": sched, "max_bps": maxBps, "quota_bytes": quota})
			return
		}
		var req struct {
			Schedule   string `json:"schedule"`
			MaxBps     int64  `json:"max_bps"`
			QuotaBytes int64  `json:"quota_bytes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		h.db.SetPeerLimits(token, strings.TrimSpace(req.Schedule), req.MaxBps, req.QuotaBytes)
		h.db.RecordEvent("limits", short+" limits updated")
	}
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, _ := h.db.Query(`SELECT domain,reason FROM blocklist ORDER BY domain`)
		if rows != nil {
			defer rows.Close()
		}
		list := []map[string]string{}
		if rows != nil {
			for rows.Next() {
				var d, rsn string
				rows.Scan(&d, &rsn)
				list = append(list, map[string]string{"domain": d, "reason": rsn})
			}
		}
		if list == nil {
			list = []map[string]string{}
		}
		json.NewEncoder(w).Encode(list)
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Reason string `json:"reason"`
		Clear  bool   `json:"clear"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if r.Method == "POST" {
		if req.Domain == "" {
			http.Error(w, "domain required", 400)
			return
		}
		h.db.Exec(`INSERT OR REPLACE INTO blocklist(domain,reason) VALUES(?,?)`, req.Domain, req.Reason)
		h.db.RecordEvent("blocklist", req.Domain+" blocked")
	} else if r.Method == "DELETE" {
		if req.Clear || req.Domain == "" {
			h.db.Exec(`DELETE FROM blocklist`)
			h.db.RecordEvent("blocklist", "blocklist cleared")
		} else {
			h.db.Exec(`DELETE FROM blocklist WHERE domain=?`, req.Domain)
			h.db.RecordEvent("blocklist", req.Domain+" unblocked")
		}
	}
	invalidateBlockCache()
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiStats(w http.ResponseWriter, r *http.Request) {
	var totalUp, totalDown int64
	var active, pending, banned, kicked, expired, blocked, total, online int
	h.db.QueryRow(`SELECT COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM peers`).Scan(&totalUp, &totalDown)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='approved'`).Scan(&active)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='pending'`).Scan(&pending)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='banned'`).Scan(&banned)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='kicked'`).Scan(&kicked)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='expired'`).Scan(&expired)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&total)
	h.db.QueryRow(`SELECT COUNT(*) FROM blocklist`).Scan(&blocked)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE last_seen > datetime('now','-5 minutes')`).Scan(&online)

	// Sessions by country (offline GeoIP on last seen source IP).
	countries := map[string]int{}
	if h.geo != nil {
		rows, err := h.db.Query(`SELECT COALESCE(last_ip,'') FROM peers WHERE status='approved' AND last_ip != ''`)
		if err == nil {
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					if name := h.geo.CountryName(ip); name != "" {
						countries[name]++
					}
				}
			}
			rows.Close()
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_up": totalUp, "total_down": totalDown,
		"active": active, "pending": pending, "banned": banned,
		"kicked": kicked, "expired": expired, "total": total, "blocked": blocked,
		"online": online, "kill_switch": h.db.KillSwitch(), "countries": countries,
	})
}

func (h *Handler) apiReport(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(h.db.WeeklyReport())
}

func (h *Handler) apiVisits(w http.ResponseWriter, r *http.Request) {
	// Aggregated for privacy: domain -> total hits, no per-peer URLs, no IP
	rows, err := h.db.Query(`SELECT domain, SUM(hits) as hits, MAX(last_seen) as last FROM visits GROUP BY domain ORDER BY hits DESC LIMIT 100`)
	if err != nil {
		json.NewEncoder(w).Encode([]map[string]any{})
		return
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var domain string
		var hits int
		var last string
		rows.Scan(&domain, &hits, &last)
		out = append(out, map[string]any{"domain": domain, "hits": hits, "last": last})
	}
	if out == nil {
		out = []map[string]any{}
	}
	json.NewEncoder(w).Encode(out)
}

func (h *Handler) apiAbuse(w http.ResponseWriter, r *http.Request) {
	// Abuse protection stats: rate-limited IPs, banned fingerprints, recent blocks
	var rateLimited, bannedFP int
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='banned'`).Scan(&bannedFP)
	// Guard stats if available (approx)
	rateLimited = 0
	json.NewEncoder(w).Encode(map[string]any{
		"banned":       bannedFP,
		"rate_limited": rateLimited,
		"note":         "Abuse protection: per-IP 10/min, per-peer 100 domains/10s -> temp kick, fingerprint+IP hard ban, easy unban via panel. Oracle decoy: normal apt cron + decoy site traffic.",
	})
}

func (h *Handler) apiEvents(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(h.db.RecentEvents(50))
}

func (h *Handler) apiSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		sshMax, sshDaily, sshTrickle := h.db.SSHTierLimits()
		resp := map[string]any{
			"kill_switch":        h.db.KillSwitch(),
			"kill_switch_reason": h.db.KillSwitchReason(),
			"kill_switch_allow":  h.db.KillSwitchAllowList(),
			// ssh-tier containment (sshtier.go): effective values, 0 = off.
			"ssh_tier_max_bps":      sshMax,
			"ssh_tier_daily_mb":     sshDaily >> 20,
			"ssh_tier_trickle_kbps": sshTrickle * 8 / 1000,
		}
		if until := h.db.AutoAcceptUntil(); !until.IsZero() {
			resp["auto_accept_until"] = until.Format(time.RFC3339)
			resp["auto_accept_active"] = h.db.AutoAcceptActive()
		} else {
			resp["auto_accept_active"] = false
		}
		json.NewEncoder(w).Encode(resp)
		return
	}
	var req struct {
		KillSwitch     *bool     `json:"kill_switch"`
		KillReason     *string   `json:"kill_switch_reason"`
		KillAllow      *[]string `json:"kill_switch_allow"`
		AutoAcceptMin  *int      `json:"auto_accept_minutes"`   // >0 open for N minutes; 0 close now
		SSHMaxBps      *int64    `json:"ssh_tier_max_bps"`      // sustained ssh-ingress cap, bytes/sec
		SSHDailyMB     *int64    `json:"ssh_tier_daily_mb"`     // per-device daily ssh budget, MB
		SSHTrickleKbps *int64    `json:"ssh_tier_trickle_kbps"` // post-budget rate, kbps
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil ||
		(req.KillSwitch == nil && req.AutoAcceptMin == nil && req.KillReason == nil && req.KillAllow == nil &&
			req.SSHMaxBps == nil && req.SSHDailyMB == nil && req.SSHTrickleKbps == nil) {
		http.Error(w, "kill_switch, kill_switch_reason, kill_switch_allow, auto_accept_minutes or ssh_tier_* required", 400)
		return
	}
	if req.KillReason != nil {
		reason := strings.TrimSpace(*req.KillReason)
		if len(reason) > 500 {
			http.Error(w, "reason too long (max 500)", 400)
			return
		}
		h.db.SetSetting("kill_switch_reason", reason)
	}
	if req.KillAllow != nil {
		if len(*req.KillAllow) > 64 {
			http.Error(w, "allowlist too large (max 64)", 400)
			return
		}
		clean := make([]string, 0, len(*req.KillAllow))
		for _, t := range *req.KillAllow {
			if t = strings.TrimSpace(t); t == "" {
				continue
			}
			if !validTokenCharset(t) {
				http.Error(w, "invalid token in allowlist", 400)
				return
			}
			clean = append(clean, t)
		}
		h.db.SetSetting("kill_switch_allow", strings.Join(clean, ","))
		h.db.RecordEvent("kill-switch", "allowlist updated ("+strings.Join(shortTokens(clean), ", ")+")")
	}
	if req.SSHMaxBps != nil || req.SSHDailyMB != nil || req.SSHTrickleKbps != nil {
		if req.SSHMaxBps != nil {
			v := *req.SSHMaxBps
			if v < 0 || v > 1_000_000_000 { // ≤ 1 GB/s
				http.Error(w, "ssh_tier_max_bps out of range (0..1e9)", 400)
				return
			}
			h.db.SetSetting("ssh_tier_max_bps", strconv.FormatInt(v, 10))
		}
		if req.SSHDailyMB != nil {
			v := *req.SSHDailyMB
			if v < 0 || v > 1_000_000 { // ≤ 1 TB/day per device
				http.Error(w, "ssh_tier_daily_mb out of range (0..1e6)", 400)
				return
			}
			h.db.SetSetting("ssh_tier_daily_mb", strconv.FormatInt(v, 10))
		}
		if req.SSHTrickleKbps != nil {
			v := *req.SSHTrickleKbps
			if v < 0 || v > 1_000_000 {
				http.Error(w, "ssh_tier_trickle_kbps out of range (0..1e6)", 400)
				return
			}
			h.db.SetSetting("ssh_tier_trickle_kbps", strconv.FormatInt(v, 10))
		}
		h.db.RecordEvent("ssh-tier", "containment policy updated")
	}
	if req.AutoAcceptMin != nil {
		until := h.db.SetAutoAccept(*req.AutoAcceptMin)
		if until.IsZero() {
			h.db.RecordEvent("auto-accept", "auto-accept window closed")
			h.db.RecordAlert("info", "nac", "auto-accept window closed — new devices need approval again")
		} else {
			h.db.RecordEvent("auto-accept", "auto-accept window open until "+until.Format("2006-01-02 15:04:05")+" UTC")
			h.db.RecordAlert("warning", "nac", "auto-accept OPEN until "+until.Format("2006-01-02 15:04:05")+" UTC — new devices are approved instantly")
		}
	}
	if req.KillSwitch != nil {
		h.db.SetKillSwitch(*req.KillSwitch)
		if *req.KillSwitch {
			h.db.RecordEvent("kill-switch", "all tunnel traffic suspended")
			h.db.RecordAlert("critical", "kill-switch", "KILL SWITCH ENGAGED — all tunnel traffic suspended")
		} else {
			h.db.RecordEvent("kill-switch", "tunnel traffic resumed")
			h.db.RecordAlert("info", "kill-switch", "kill switch released — traffic resumed")
		}
	}
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		json.NewEncoder(w).Encode(h.db.Categories())
		return
	}
	var req struct {
		Category string `json:"category"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !h.db.SetCategoryEnabled(req.Category, req.Enabled) {
		http.Error(w, "unknown category", 400)
		return
	}
	state := "disabled"
	if req.Enabled {
		state = "enabled"
	}
	h.db.RecordEvent("category", req.Category+" blocking "+state)
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) tokenRequest(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if !h.regAllowed(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10) // 16 KB is plenty for registration
	var req struct {
		Token       string `json:"token"`
		Fingerprint string `json:"fingerprint"`
		DeviceName  string `json:"device_name"`
		SSHPubKey   string `json:"ssh_pubkey"`
	}
	json.NewDecoder(r.Body).Decode(&req)
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
	// Hard ban on fingerprint OR device public key: a banned device cannot
	// shed the ban by minting a fresh token.
	if h.db.IdentityBanned(req.Fingerprint, strings.TrimSpace(req.SSHPubKey)) {
		http.Error(w, "device banned", 403)
		return
	}
	// New devices start pending unless auto-approve is configured or the
	// admin has opened a temporary auto-accept window.
	status := "pending"
	if h.autoApprove || h.db.AutoAcceptActive() {
		status = "approved"
	}
	// Only set status on first insert; existing peers keep their current status
	res, _ := h.db.Exec(`INSERT OR IGNORE INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen) VALUES(?,?,?, ?, ?, datetime('now'), datetime('now'))`,
		req.Token, req.Fingerprint, req.DeviceName, req.SSHPubKey, status)
	if n, _ := res.RowsAffected(); n == 0 {
		h.db.Exec(`UPDATE peers SET last_seen=datetime('now'), ssh_pubkey=COALESCE(NULLIF(ssh_pubkey,''),?) WHERE token=?`, req.SSHPubKey, req.Token)
		var existingStatus string
		h.db.QueryRow(`SELECT status FROM peers WHERE token=?`, req.Token).Scan(&existingStatus)
		status = existingStatus
		// A device that registered before an auto-accept window opened must
		// not stay stuck pending forever: while the window is open, upgrade
		// it and install its SSH key so early launchers connect too.
		if status == "pending" && h.db.AutoAcceptActive() {
			h.db.Exec(`UPDATE peers SET status='approved' WHERE token=?`, req.Token)
			status = "approved"
			h.db.RecordEvent("auto-accept", req.DeviceName+" upgraded to approved (auto-accept window)")
			if h.OnApprove != nil {
				h.OnApprove(req.Token)
			}
		}
	} else {
		h.db.RecordEvent("register", req.DeviceName+" registered ("+status+")")
		h.db.RecordAlert("info", "nac", "new device "+req.DeviceName+" registered — status: "+status)
		// Auto-approved via the window: install the SSH key now so
		// standalone clients can use the ssh tier immediately.
		if status == "approved" && h.OnApprove != nil && !h.autoApprove {
			h.OnApprove(req.Token)
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func (h *Handler) tokenStatus(w http.ResponseWriter, r *http.Request) {
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
	var status, kickReason, banReason, kickExpires string
	err := h.db.QueryRow(`SELECT status, COALESCE(kick_reason,''), COALESCE(ban_reason,''), COALESCE(kick_expires,'') FROM peers WHERE token=?`, token).
		Scan(&status, &kickReason, &banReason, &kickExpires)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", 404)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"status": status, "kick_reason": kickReason, "ban_reason": banReason, "kick_expires": kickExpires,
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
	var req struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	h.db.Exec(`UPDATE peers SET last_seen=datetime('now') WHERE token=?`, req.Token)
	w.Write([]byte(`{"ok":true}`))
}

// tokenHealth ingests client telemetry (device posture for NAC/inventory).
// Public but rate-limited per IP; unknown tokens are ignored.
func (h *Handler) tokenHealth(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if !h.regAllowed(clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10) // telemetry is tiny
	var req struct {
		Token        string  `json:"token"`
		Version      string  `json:"version"`
		OS           string  `json:"os"`
		Arch         string  `json:"arch"`
		CPUPct       float64 `json:"cpu_pct"`
		MemPct       float64 `json:"mem_pct"`
		TempC        float64 `json:"temp_c"`
		UptimeS      int64   `json:"uptime_s"`
		LatencyMs    float64 `json:"latency_ms"`
		JitterMs     float64 `json:"jitter_ms"`
		ProbeLossPct float64 `json:"probe_loss_pct"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "bad request", 400)
		return
	}
	// Bounded telemetry strings (token length is enforced at registration).
	if len(req.Version) > 64 || len(req.OS) > 64 || len(req.Arch) > 32 {
		http.Error(w, "field too long", 400)
		return
	}
	var n int
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE token=?`, req.Token).Scan(&n)
	if n == 0 {
		http.Error(w, "not found", 404)
		return
	}
	h.db.RecordHealth(req.Token, req.Version, req.OS, req.Arch, req.CPUPct, req.MemPct, req.TempC, req.UptimeS, req.LatencyMs, req.JitterMs, req.ProbeLossPct)
	h.db.Exec(`UPDATE peers SET last_seen=datetime('now') WHERE token=?`, req.Token)
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			ID  int64 `json:"id"`
			Ack bool  `json:"ack"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == 0 {
			http.Error(w, "bad request", 400)
			return
		}
		if req.Ack {
			h.db.AckAlert(req.ID)
		}
		w.Write([]byte(`{"ok":true}`))
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"alerts":  h.db.Alerts(60),
		"unacked": h.db.UnackedAlertCount(),
	})
}

// apiDevices returns the device inventory: peers joined with telemetry.
func (h *Handler) apiDevices(w http.ResponseWriter, r *http.Request) {
	devices := h.db.AllHealth()
	if h.geo != nil {
		for i := range devices {
			if devices[i].LastIP != "" {
				devices[i].Country = h.geo.CountryName(devices[i].LastIP)
			}
		}
	}
	json.NewEncoder(w).Encode(devices)
}
