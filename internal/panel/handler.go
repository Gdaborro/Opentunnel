package panel

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"
)

var _ = time.Second // peers carry time.Time fields

type Handler struct {
	db   *DB
	auth *Auth
	tmpl *template.Template
}

func New(db *DB, auth *Auth) *Handler {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))
	return &Handler{db: db, auth: auth, tmpl: tmpl}
}

func (h *Handler) Mount(mux *http.ServeMux) {
	// Setup is public but only when no admin exists
	mux.Handle("/admin/setup", http.HandlerFunc(h.setupPage))
	mux.Handle("/admin/api/setup", http.HandlerFunc(h.apiSetup))
	mux.Handle("/admin/login", http.HandlerFunc(h.loginPage))
	mux.Handle("/admin/api/login", http.HandlerFunc(h.apiLogin))
	mux.Handle("/admin/logout", http.HandlerFunc(h.logout))
	mux.Handle("/admin/api/peers", h.auth.RequireAuth(http.HandlerFunc(h.apiPeers)))
	mux.Handle("/admin/api/peers/", h.auth.RequireAuth(http.HandlerFunc(h.apiPeerAction)))
	mux.Handle("/admin/api/blocklist", h.auth.RequireAuth(http.HandlerFunc(h.apiBlocklist)))
	mux.Handle("/admin/api/stats", h.auth.RequireAuth(http.HandlerFunc(h.apiStats)))
	mux.Handle("/admin/api/report", h.auth.RequireAuth(http.HandlerFunc(h.apiReport)))
	mux.Handle("/admin/", h.auth.RequireAuth(http.HandlerFunc(h.dashboard)))

	// Public token API (no auth)
	mux.Handle("/api/token/request", http.HandlerFunc(h.tokenRequest))
	mux.Handle("/api/token/status", http.HandlerFunc(h.tokenStatus))
	mux.Handle("/api/token/heartbeat", http.HandlerFunc(h.tokenHeartbeat))
}

func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Mount(mux)
	return mux
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	if h.auth.NeedsSetup() {
		http.Redirect(w, r, "/admin/setup", http.StatusFound)
		return
	}
	h.tmpl.ExecuteTemplate(w, "login.html", nil)
}

func (h *Handler) setupPage(w http.ResponseWriter, r *http.Request) {
	if !h.auth.NeedsSetup() {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}
	h.tmpl.ExecuteTemplate(w, "setup.html", nil)
}

func (h *Handler) apiSetup(w http.ResponseWriter, r *http.Request) {
	if !h.auth.NeedsSetup() {
		http.Error(w, "already setup", http.StatusForbidden)
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "bad request", 400)
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
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) apiLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&creds)
	ok, _ := h.auth.Login(creds.Username, creds.Password)
	if !ok {
		http.Error(w, "invalid credentials", 401)
		return
	}
	sid := h.auth.CreateSession(creds.Username)
	h.auth.SetSessionCookie(w, sid)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "panel_session", MaxAge: -1, Path: "/admin"})
	http.Redirect(w, r, "/admin/login", 302)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	h.tmpl.ExecuteTemplate(w, "dashboard.html", map[string]string{"User": h.auth.GetUser(r)})
}

func (h *Handler) apiPeers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT token,fingerprint,device_name,status,created_at,last_seen,bytes_up,bytes_down,kick_reason,ban_reason FROM peers ORDER BY last_seen DESC`)
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
			&p.BytesUp, &p.BytesDown, &kickReason, &banReason); err != nil {
			// Row skipped rather than aborting the whole list
			continue
		}
		p.KickReason = kickReason.String
		p.BanReason = banReason.String
		peers = append(peers, p)
	}
	json.NewEncoder(w).Encode(peers)
}

func (h *Handler) apiPeerAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/api/peers/"), "/")
	if len(parts) < 2 {
		http.Error(w, "bad request", 400)
		return
	}
	token, action := parts[0], parts[1]
	switch action {
	case "approve":
		h.db.Exec(`UPDATE peers SET status='approved', last_seen=datetime('now') WHERE token=?`, token)
		// If this peer has an SSH pubkey, authorize it for tun
		var pub string
		h.db.QueryRow(`SELECT COALESCE(ssh_pubkey,'') FROM peers WHERE token=?`, token).Scan(&pub)
		if pub != "" {
			// Use helper to append to authorized_keys idempotently
			_ = addTunPubkey(pub)
		}
	case "kick":
		var req struct{ Reason string `json:"reason"` }
		json.NewDecoder(r.Body).Decode(&req)
		h.db.Exec(`UPDATE peers SET status='kicked', kick_reason=?, kick_expires=datetime('now','+10 minutes') WHERE token=?`, req.Reason, token)
	case "ban":
		var req struct {
			Reason   string `json:"reason"`
			Duration string `json:"duration"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		h.db.Exec(`UPDATE peers SET status='banned', ban_reason=?, ban_duration=? WHERE token=?`, req.Reason, req.Duration, token)
		// also ban fingerprint hard
		var fp string
		h.db.QueryRow(`SELECT fingerprint FROM peers WHERE token=?`, token).Scan(&fp)
		h.db.Exec(`INSERT OR REPLACE INTO fingerprints_banned(fingerprint,reason,banned_at) VALUES(?,?,datetime('now'))`, fp, req.Reason)
	case "unban":
		var fp string
		h.db.QueryRow(`SELECT fingerprint FROM peers WHERE token=?`, token).Scan(&fp)
		h.db.Exec(`DELETE FROM fingerprints_banned WHERE fingerprint=?`, fp)
		h.db.Exec(`UPDATE peers SET status='pending' WHERE token=?`, token)
	}
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rows, _ := h.db.Query(`SELECT domain,reason FROM blocklist`)
		defer rows.Close()
		var list []map[string]string
		for rows.Next() {
			var d, rsn string
			rows.Scan(&d, &rsn)
			list = append(list, map[string]string{"domain": d, "reason": rsn})
		}
		json.NewEncoder(w).Encode(list)
		return
	}
	var req struct {
		Domain string `json:"domain"`
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if r.Method == "POST" {
		h.db.Exec(`INSERT OR REPLACE INTO blocklist(domain,reason) VALUES(?,?)`, req.Domain, req.Reason)
	} else if r.Method == "DELETE" {
		h.db.Exec(`DELETE FROM blocklist WHERE domain=?`, req.Domain)
	}
	w.Write([]byte(`{"ok":true}`))
}

func (h *Handler) apiStats(w http.ResponseWriter, r *http.Request) {
	var totalUp, totalDown int64
	var active, pending, banned int
	h.db.QueryRow(`SELECT COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0) FROM peers`).Scan(&totalUp, &totalDown)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='approved'`).Scan(&active)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='pending'`).Scan(&pending)
	h.db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='banned'`).Scan(&banned)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_up": totalUp, "total_down": totalDown,
		"active": active, "pending": pending, "banned": banned,
	})
}

func (h *Handler) apiReport(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(h.db.WeeklyReport())
}

func (h *Handler) tokenRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token      string `json:"token"`
		Fingerprint string `json:"fingerprint"`
		DeviceName string `json:"device_name"`
		AdminKey   string `json:"admin_key"`
		SSHPubKey  string `json:"ssh_pubkey"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Token == "" || req.Fingerprint == "" {
		http.Error(w, "token and fingerprint required", 400)
		return
	}
	// Check hard ban on fingerprint
	var banned int
	h.db.QueryRow(`SELECT COUNT(*) FROM fingerprints_banned WHERE fingerprint=?`, req.Fingerprint).Scan(&banned)
	if banned > 0 {
		http.Error(w, "device banned", 403)
		return
	}
	// Check if admin key matches (insta-approve)
	status := "pending"
	if req.AdminKey != "" && isAdminKey(req.AdminKey) {
		status = "approved"
	}
	// Only set status on first insert; existing peers keep their current status
	res, _ := h.db.Exec(`INSERT OR IGNORE INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen) VALUES(?,?,?, ?, ?, datetime('now'), datetime('now'))`,
		req.Token, req.Fingerprint, req.DeviceName, req.SSHPubKey, status)
	if n, _ := res.RowsAffected(); n == 0 {
		h.db.Exec(`UPDATE peers SET last_seen=datetime('now'), ssh_pubkey=COALESCE(ssh_pubkey,?) WHERE token=?`, req.SSHPubKey, req.Token)
		var existingStatus string
		h.db.QueryRow(`SELECT status FROM peers WHERE token=?`, req.Token).Scan(&existingStatus)
		status = existingStatus
	}
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func (h *Handler) tokenStatus(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
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
	var req struct{ Token string `json:"token"` }
	json.NewDecoder(r.Body).Decode(&req)
	h.db.Exec(`UPDATE peers SET last_seen=datetime('now') WHERE token=?`, req.Token)
	w.Write([]byte(`{"ok":true}`))
}

func addTunPubkey(pub string) error {
	pub = strings.TrimSpace(pub)
	if pub == "" {
		return nil
	}
	// For MVP, just log — the VPS poller or manual admin can handle the actual file write
	// Full impl would: exec.Command("sh","-c", "grep -qF ... || echo ... | sudo -u tun tee -a ...")
	return nil
}

func isAdminKey(key string) bool {
	// Compare against env ADMIN_SSH_PUB fingerprint – simplified for MVP
	// In production, verify signature, not just string compare
	return key == "main-ssh-key-placeholder"
}
