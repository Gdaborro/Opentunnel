package panel

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	db       *DB
	sessions map[string]string // sessionID -> username
	mu       sync.RWMutex
}

func NewAuth(db *DB) *Auth {
	return &Auth{db: db, sessions: make(map[string]string)}
}

func (a *Auth) NeedsSetup() bool {
	var count int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&count)
	return count == 0
}

func (a *Auth) EnsureAdmin(username, password string) error {
	var count int
	a.db.QueryRow(`SELECT COUNT(*) FROM admins WHERE username=?`, username).Scan(&count)
	if count > 0 {
		return nil
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)
	_, err := a.db.Exec(`INSERT INTO admins(username,password_hash) VALUES(?,?)`, username, string(hash))
	return err
}

func (a *Auth) CreateAdmin(username, password string) error {
	if !a.NeedsSetup() {
		return sql.ErrNoRows
	}
	if len(username) < 3 || len(password) < 8 {
		return sql.ErrTxDone
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)
	_, err := a.db.Exec(`INSERT INTO admins(username,password_hash) VALUES(?,?)`, username, string(hash))
	return err
}

func (a *Auth) Login(username, password string) (bool, error) {
	var hash string
	err := a.db.QueryRow(`SELECT password_hash FROM admins WHERE username=?`, username).Scan(&hash)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

func (a *Auth) CreateSession(username string) string {
	b := make([]byte, 32)
	rand.Read(b)
	sid := base64.RawURLEncoding.EncodeToString(b)
	a.mu.Lock()
	a.sessions[sid] = username
	a.mu.Unlock()
	return sid
}

func (a *Auth) GetUser(r *http.Request) string {
	c, err := r.Cookie("panel_session")
	if err != nil {
		return ""
	}
	a.mu.RLock()
	u := a.sessions[c.Value]
	a.mu.RUnlock()
	return u
}

func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Setup is always public (but handler will reject if already setup)
	if r.URL.Path == "/admin/login" || r.URL.Path == "/admin/api/login" || r.URL.Path == "/admin/setup" || r.URL.Path == "/admin/api/setup" {
			next.ServeHTTP(w, r)
			return
		}
		if a.NeedsSetup() {
			http.Redirect(w, r, "/admin/setup", http.StatusFound)
			return
		}
		if a.GetUser(r) == "" {
			if strings.HasPrefix(r.URL.Path, "/admin/api/") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) SetSessionCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "panel_session",
		Value:    sid,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})
}
