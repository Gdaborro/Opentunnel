package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"opentunnel/internal/serverpool"
)

func (h *Handler) WithServerPool(id string, loginRequired bool) (*Handler, error) {
	info, err := h.db.BindServerPool(id, loginRequired)
	if err != nil {
		return nil, err
	}
	h.poolID, h.enrollmentLogin = id, loginRequired
	h.poolAuthorityID = info.AuthorityID
	return h, nil
}

func (h *Handler) serverInfo(w http.ResponseWriter, r *http.Request) {
	if h.poolID == "" || !serverpool.ValidID(h.poolID) || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	if !h.rateAllowed(clientIP(r), 60, time.Minute, "pool-info") {
		http.Error(w, "capability check rate limited", http.StatusTooManyRequests)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(serverpool.Info{Version: 1, PoolID: h.poolID, AuthorityID: h.poolAuthorityID, LoginRequired: h.enrollmentLogin, ApprovalRequired: true})
}

type enrollmentRequest struct {
	PoolID      string `json:"pool_id"`
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	DeviceName  string `json:"device_name"`
	SSHPubKey   string `json:"ssh_pubkey"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
}

func (h *Handler) poolTokenStatus(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if !h.rateAllowed(clientIP(r), 60, time.Minute, "status") {
		http.Error(w, "rate limited", 429)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		http.Error(w, "invalid status request", 400)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := serverpool.DecodeStrict(raw, &req); err != nil || len(req.Token) < 16 || len(req.Token) > 1024 || !validTokenCharset(req.Token) {
		http.Error(w, "invalid status request", 400)
		return
	}
	p, err := h.db.AccessPolicy(req.Token)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", 404)
		return
	}
	if err != nil {
		http.Error(w, "status unavailable", 503)
		return
	}
	if !h.verifyHTTPProof(r, req.Token, raw) {
		http.Error(w, "device proof required", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": p.Status, "kick_reason": p.Reason, "ban_reason": p.Reason, "kick_expires": p.Expires})
}

func decodeEnrollmentRequest(w http.ResponseWriter, r *http.Request) (enrollmentRequest, []byte, error) {
	var req enrollmentRequest
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil {
		return req, raw, err
	}
	if err := serverpool.DecodeStrict(raw, &req); err != nil {
		return req, raw, errors.New("invalid enrollment schema")
	}
	if len(req.Token) < 16 || len(req.Token) > 1024 || !validTokenCharset(req.Token) || len(req.Fingerprint) < 1 || len(req.Fingerprint) > 128 || len(req.DeviceName) > 64 || len(req.SSHPubKey) > 2048 || len(req.Username) > 64 || len(req.Password) > 72 {
		return req, raw, errors.New("invalid enrollment fields")
	}
	return req, raw, nil
}

func (h *Handler) enrollPool(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	if !serverpool.ValidID(h.poolID) {
		http.Error(w, "pool unavailable", 503)
		return
	}
	if !h.regAllowed(clientIP(r)) {
		http.Error(w, "enrollment rate limited", 429)
		return
	}
	req, raw, err := decodeEnrollmentRequest(w, r)
	defer clear(raw)
	if err != nil || req.PoolID != h.poolID {
		http.Error(w, "invalid pool enrollment request", 400)
		return
	}
	pub, ok := CanonicalSSHPubKey(req.SSHPubKey)
	if !ok || !h.verifyKeyHTTPProof(r, pub, raw) {
		http.Error(w, "device-key possession proof required", 403)
		return
	}
	req.SSHPubKey = pub
	if (req.Username != "" || req.Password != "") && !h.enrollmentLogin {
		http.Error(w, "this pool does not accept password enrollment", 400)
		return
	}
	var account *verifiedEnrollmentAccount
	if req.Username != "" || req.Password != "" {
		// The client checks pins; server-side refuse plaintext public entry too.
		if r.TLS == nil && !(trustedPanelProxy(r) && r.Header.Get("X-Otu-Original-Scheme") == "https") {
			http.Error(w, "verified TLS enrollment required", 403)
			return
		}
		if !validEnrollmentUsername(req.Username) || len(req.Password) < 1 {
			http.Error(w, "enrollment login required", 401)
			return
		}
		if !h.rateAllowed(clientIP(r), 6, time.Minute, "enrollment-login") {
			http.Error(w, "login rate limited", 429)
			return
		}
		select {
		case h.enrollmentSlots <- struct{}{}:
			defer func() { <-h.enrollmentSlots }()
		default:
			http.Error(w, "enrollment authentication busy", 429)
			return
		}
		var err error
		account, err = h.db.verifyEnrollmentAccount(r.Context(), req.Username, req.Password)
		if err != nil {
			http.Error(w, "enrollment login unavailable", 503)
			return
		}
		if account == nil {
			http.Error(w, "enrollment login required", 401)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, created, err := h.db.enrollPool(ctx, req, h.enrollmentLogin, account)
	switch {
	case errors.Is(err, errEnrollmentNeedsLogin):
		http.Error(w, "enrollment login required", 401)
		return
	case errors.Is(err, errEnrollmentIdentityConflict):
		http.Error(w, "stored identity differs; administrator verification required", 409)
		return
	case errors.Is(err, errEnrollmentDenied):
		http.Error(w, "account or identity is not eligible for enrollment", 403)
		return
	case err != nil:
		http.Error(w, "enrollment unavailable; no device approved", 503)
		return
	}
	if created {
		h.db.SetPeerIP(req.Token, clientIP(r))
		h.db.RecordAlert("info", "enrollment", "new device enrollment awaits manual approval")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
	}{status})
}

var (
	errEnrollmentNeedsLogin       = errors.New("enrollment login required")
	errEnrollmentIdentityConflict = errors.New("enrollment identity conflict")
	errEnrollmentDenied           = errors.New("enrollment denied")
)

type verifiedEnrollmentAccount struct {
	username string
	hash     string
}

// Bcrypt is performed without holding the SQLite writer lock. Recheck the
// account's exact enabled/hash state inside the enrollment transaction.
func (db *DB) verifyEnrollmentAccount(parent context.Context, username, password string) (*verifiedEnrollmentAccount, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	var hash string
	var enabled bool
	err := db.QueryRowContext(ctx, `SELECT password_hash, enabled FROM enrollment_accounts WHERE username=?`, username).Scan(&hash, &enabled)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == sql.ErrNoRows || !enabled {
		hash = dummyEnrollmentHash
	}
	valid := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	if !valid || err == sql.ErrNoRows || !enabled {
		return nil, nil
	}
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	return &verifiedEnrollmentAccount{username: username, hash: hash}, nil
}

func (db *DB) enrollPool(ctx context.Context, req enrollmentRequest, loginRequired bool, account *verifiedEnrollmentAccount) (status string, created bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	var banned int
	var poolID string
	var authorityLogin bool
	if err := tx.QueryRowContext(ctx, `SELECT pool_id,login_required FROM server_pool_authority WHERE id=1`).Scan(&poolID, &authorityLogin); err != nil {
		return "", false, err
	}
	if poolID != req.PoolID || authorityLogin != loginRequired {
		return "", false, errEnrollmentDenied
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM fingerprints_banned WHERE fingerprint=?) OR EXISTS(SELECT 1 FROM pubkeys_banned WHERE pubkey=?)`, req.Fingerprint, req.SSHPubKey).Scan(&banned); err != nil {
		return "", false, err
	}
	if banned != 0 {
		return "", false, errEnrollmentDenied
	}
	var existingKey, existingFP, enrolledUser, enrolledPool, enrolledKey string
	err = tx.QueryRowContext(ctx, `SELECT p.status, COALESCE(p.ssh_pubkey,''), p.fingerprint, COALESCE(e.username,''), COALESCE(e.pool_id,''), COALESCE(e.public_key,'') FROM peers p LEFT JOIN peer_enrollments e ON e.token=p.token WHERE p.token=?`, req.Token).Scan(&status, &existingKey, &existingFP, &enrolledUser, &enrolledPool, &enrolledKey)
	if err == nil {
		if existingKey != req.SSHPubKey || existingFP != req.Fingerprint {
			return "", false, errEnrollmentIdentityConflict
		}
		if status == "banned" {
			return "", false, errEnrollmentDenied
		}
		if enrolledPool != poolID || enrolledKey != req.SSHPubKey || (loginRequired && enrolledUser == "") {
			if loginRequired && account == nil {
				return "", false, errEnrollmentNeedsLogin
			}
			// Migrating a pre-account row permits enrollment only, and returns
			// it to pending. Password login must never inherit old approval.
			if account != nil && enrolledUser != "" && enrolledUser != account.username {
				return "", false, errEnrollmentIdentityConflict
			}
			if err := bindEnrollmentAccount(ctx, tx, req, account); err != nil {
				return "", false, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE peers SET status='pending', approval_required=1, auth_epoch=hex(randomblob(16)) WHERE token=?`, req.Token); err != nil {
				return "", false, err
			}
			status = "pending"
		} else if account != nil && enrolledUser != "" && enrolledUser != account.username {
			return "", false, errEnrollmentIdentityConflict
		}
		// Existing key-authenticated enrollment does not need a password at
		// each startup; the server still checks actual approval for traffic.
		return status, false, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return "", false, err
	}
	if loginRequired && account == nil {
		return "", false, errEnrollmentNeedsLogin
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers WHERE status='pending'`).Scan(&count); err != nil {
		return "", false, err
	}
	if count >= 4096 {
		return "", false, errEnrollmentDenied
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen,auth_epoch,approval_required) VALUES(?,?,?,?,'pending',datetime('now'),datetime('now'),hex(randomblob(16)),1)`, req.Token, req.Fingerprint, req.DeviceName, req.SSHPubKey); err != nil {
		return "", false, err
	}
	if err := bindEnrollmentAccount(ctx, tx, req, account); err != nil {
		return "", false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('enrollment','device-key enrollment created; manual approval required')`); err != nil {
		return "", false, err
	}
	return "pending", true, tx.Commit()
}

func bindEnrollmentAccount(ctx context.Context, tx *sql.Tx, req enrollmentRequest, account *verifiedEnrollmentAccount) error {
	username := ""
	if account != nil {
		var hash string
		var enabled bool
		var maxDevices, devices int
		if err := tx.QueryRowContext(ctx, `SELECT password_hash,enabled,max_devices,(SELECT COUNT(*) FROM peer_enrollments e JOIN peers p ON p.token=e.token WHERE e.username=a.username AND e.token!=?) FROM enrollment_accounts a WHERE username=?`, req.Token, account.username).Scan(&hash, &enabled, &maxDevices, &devices); err != nil {
			return err
		}
		if !enabled || hash != account.hash || devices >= maxDevices {
			return errEnrollmentDenied
		}
		username = account.username
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO peer_enrollments(token,username,pool_id,public_key) VALUES(?,?,?,?) ON CONFLICT(token) DO UPDATE SET username=excluded.username,pool_id=excluded.pool_id,public_key=excluded.public_key,created_at=CURRENT_TIMESTAMP`, req.Token, username, req.PoolID, req.SSHPubKey)
	return err
}

func validEnrollmentUsername(name string) bool {
	if len(name) < 3 || len(name) > 64 || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if r != '.' && r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// A fixed, valid cost-12 hash avoids an unknown-account timing shortcut. The
// corresponding value is a public dummy, not an account credential.
const dummyEnrollmentHash = "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
