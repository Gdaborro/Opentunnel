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
	sessions map[string]*session // sessionID -> session
	mu       sync.RWMutex

	// login throttle: per-IP failed attempts
	lmu   sync.Mutex
	fails map[string]*loginFail
}

type session struct {
	user    string
	created time.Time
}

type loginFail struct {
	count int
	until time.Time // locked until this time
	last  time.Time
}

const (
	sessionTTL      = 24 * time.Hour
	loginMaxFails   = 5
	loginLockWindow = 15 * time.Minute
)

func NewAuth(db *DB) *Auth {
	return &Auth{db: db, sessions: make(map[string]*session), fails: make(map[string]*loginFail)}
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
	a.sessions[sid] = &session{user: username, created: time.Now()}
	a.mu.Unlock()
	return sid
}

// DestroySession invalidates a session server-side (logout).
func (a *Auth) DestroySession(sid string) {
	a.mu.Lock()
	delete(a.sessions, sid)
	a.mu.Unlock()
}

func (a *Auth) GetUser(r *http.Request) string {
	c, err := r.Cookie("panel_session")
	if err != nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if !ok {
		return ""
	}
	if time.Since(s.created) > sessionTTL {
		delete(a.sessions, c.Value)
		return ""
	}
	return s.user
}

// LoginLocked reports whether the IP is currently locked out.
func (a *Auth) LoginLocked(ip string) bool {
	a.lmu.Lock()
	defer a.lmu.Unlock()
	f := a.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

// RecordLoginFail registers a failed attempt; after loginMaxFails within the
// window the IP is locked for loginLockWindow.
func (a *Auth) RecordLoginFail(ip string) {
	a.lmu.Lock()
	defer a.lmu.Unlock()
	now := time.Now()
	f := a.fails[ip]
	if f == nil || now.Sub(f.last) > loginLockWindow {
		f = &loginFail{}
		a.fails[ip] = f
	}
	f.count++
	f.last = now
	if f.count >= loginMaxFails {
		f.until = now.Add(loginLockWindow)
	}
}

// ClearLoginFail resets the counter after a successful login.
func (a *Auth) ClearLoginFail(ip string) {
	a.lmu.Lock()
	delete(a.fails, ip)
	a.lmu.Unlock()
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
