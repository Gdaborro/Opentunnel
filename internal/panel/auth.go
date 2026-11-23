package panel

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
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
	lmu         sync.Mutex
	fails       map[string]*loginFail
	bootstrapMu sync.Mutex
	loginSweep  time.Time
}

type session struct {
	user    string
	created time.Time
}

type loginFail struct {
	count    int
	inflight int
	until    time.Time // locked until this time
	last     time.Time
}

const (
	sessionTTL      = 24 * time.Hour
	loginMaxFails   = 5
	loginLockWindow = 15 * time.Minute
	maxLoginSources = 8192
)

func NewAuth(db *DB) *Auth {
	return &Auth{db: db, sessions: make(map[string]*session), fails: make(map[string]*loginFail)}
}

func (a *Auth) NeedsSetup() bool {
	var count int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&count); err != nil {
		return false
	}
	return count == 0
}

func (a *Auth) EnsureAdmin(username, password string) error {
	var count int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM admins WHERE username=?`, username).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	hash, err := generatePasswordHash(password)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`INSERT INTO admins(username,password_hash) VALUES(?,?)`, username, string(hash))
	return err
}

func (a *Auth) CreateAdmin(username, password string) error {
	a.bootstrapMu.Lock()
	defer a.bootstrapMu.Unlock()
	if !a.NeedsSetup() {
		return sql.ErrNoRows
	}
	if len(username) < 3 || len(username) > 64 || len(password) < 8 || len(password) > 72 {
		return sql.ErrTxDone
	}
	hash, err := generatePasswordHash(password)
	if err != nil {
		return err
	}
	res, err := a.db.Exec(`INSERT INTO admins(username,password_hash) SELECT ?,? WHERE NOT EXISTS(SELECT 1 FROM admins)`, username, string(hash))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.New("administrator setup already completed")
	}
	return nil
}

func (a *Auth) Login(username, password string) (bool, error) {
	if len(username) < 3 || len(username) > 64 || len(password) > 72 {
		return false, nil
	}
	release, err := passwordWork()
	if err != nil {
		return false, err
	}
	defer release()
	var hash string
	err = a.db.QueryRow(`SELECT password_hash FROM admins WHERE username=?`, username).Scan(&hash)
	missing := err == sql.ErrNoRows
	if err == sql.ErrNoRows {
		hash = dummyEnrollmentHash
	}
	if err != nil && !missing {
		return false, err
	}
	valid := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	return valid && !missing, nil
}

type loginAttempt struct {
	a    *Auth
	f    *loginFail
	once sync.Once
}

func (attempt *loginAttempt) finish(success, failed bool) {
	attempt.once.Do(func() {
		a := attempt.a
		a.lmu.Lock()
		defer a.lmu.Unlock()
		f := attempt.f
		f.inflight--
		f.last = time.Now()
		if success {
			f.count = 0
			f.until = time.Time{}
		} else if failed {
			f.count = min(f.count+1, loginMaxFails)
			if f.count >= loginMaxFails {
				f.until = f.last.Add(loginLockWindow)
			}
		}
	})
}

// Outstanding requests count toward admission before bcrypt starts. Busy/SQL
// failures release their reservation without labeling a password as incorrect.
func (a *Auth) beginLogin(ip string) (*loginAttempt, bool) {
	if ip == "" || len(ip) > 128 {
		return nil, false
	}
	a.lmu.Lock()
	defer a.lmu.Unlock()
	now := time.Now()
	a.sweepLoginsLocked(now)
	f := a.fails[ip]
	if f == nil {
		if len(a.fails) >= maxLoginSources {
			return nil, false
		}
		f = &loginFail{}
		a.fails[ip] = f
	}
	if f.inflight == 0 && now.Sub(f.last) > loginLockWindow && !now.Before(f.until) {
		f.count = 0
		f.until = time.Time{}
	}
	if now.Before(f.until) || f.count+f.inflight >= loginMaxFails {
		return nil, false
	}
	f.inflight++
	f.last = now
	return &loginAttempt{a: a, f: f}, true
}

func (a *Auth) sweepLoginsLocked(now time.Time) {
	if now.Sub(a.loginSweep) < time.Minute {
		return
	}
	a.loginSweep = now
	for ip, f := range a.fails {
		if f.inflight == 0 && now.Sub(f.last) > loginLockWindow && !now.Before(f.until) {
			delete(a.fails, ip)
		}
	}
}

func (a *Auth) CreateSession(username string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	sid := base64.RawURLEncoding.EncodeToString(b)
	a.mu.Lock()
	for sid, s := range a.sessions {
		if time.Since(s.created) > sessionTTL {
			delete(a.sessions, sid)
		}
	}
	if len(a.sessions) >= 1024 {
		a.mu.Unlock()
		return ""
	}
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
	a.sweepLoginsLocked(now)
	if len(a.fails) >= maxLoginSources && a.fails[ip] == nil {
		return
	}
	f := a.fails[ip]
	if f == nil || (f.inflight == 0 && now.Sub(f.last) > loginLockWindow && !now.Before(f.until)) {
		f = &loginFail{}
		a.fails[ip] = f
	}
	f.count = min(f.count+1, loginMaxFails)
	f.last = now
	if f.count >= loginMaxFails {
		f.until = now.Add(loginLockWindow)
	}
}

// ClearLoginFail resets the counter after a successful login.
func (a *Auth) ClearLoginFail(ip string) {
	a.lmu.Lock()
	if f := a.fails[ip]; f != nil && f.inflight > 0 {
		f.count = 0
		f.until = time.Time{}
	} else {
		delete(a.fails, ip)
	}
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
			if strings.HasPrefix(r.URL.Path, "/admin/api/") {
				http.Error(w, "unauthorized: administrator setup required", http.StatusUnauthorized)
				return
			}
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
