package panel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginThrottle(t *testing.T) {
	a := NewAuth(nil)
	ip := "203.0.113.7"
	if a.LoginLocked(ip) {
		t.Fatal("locked before any failures")
	}
	for i := 0; i < loginMaxFails-1; i++ {
		a.RecordLoginFail(ip)
	}
	if a.LoginLocked(ip) {
		t.Fatal("locked before threshold")
	}
	a.RecordLoginFail(ip)
	if !a.LoginLocked(ip) {
		t.Fatal("not locked after threshold failures")
	}
	a.ClearLoginFail(ip)
	if a.LoginLocked(ip) {
		t.Fatal("still locked after clear")
	}
}

func TestSessionLifecycle(t *testing.T) {
	a := NewAuth(nil)
	sid := a.CreateSession("alice")

	r := httptest.NewRequest("GET", "/admin/", nil)
	r.AddCookie(sessionCookie(sid))
	if u := a.GetUser(r); u != "alice" {
		t.Fatalf("GetUser = %q, want alice", u)
	}

	// Logout invalidates server-side.
	a.DestroySession(sid)
	if u := a.GetUser(r); u != "" {
		t.Fatalf("GetUser after destroy = %q, want empty", u)
	}

	// Expired sessions are rejected.
	sid2 := a.CreateSession("bob")
	a.mu.Lock()
	a.sessions[sid2].created = time.Now().Add(-sessionTTL - time.Minute)
	a.mu.Unlock()
	r2 := httptest.NewRequest("GET", "/admin/", nil)
	r2.AddCookie(sessionCookie(sid2))
	if u := a.GetUser(r2); u != "" {
		t.Fatalf("GetUser on expired session = %q, want empty", u)
	}
}

func sessionCookie(sid string) *http.Cookie {
	return &http.Cookie{Name: "panel_session", Value: sid}
}
