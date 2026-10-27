package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegisterRejectsPathStructuralTokens pins the H-1 fix (audit round
// three): a token containing "/" could not be a client-minted credential
// and made every admin action URL an injection surface.
func TestRegisterRejectsPathStructuralTokens(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	h := New(db, NewAuth(db), false)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	post := func(body map[string]string) int {
		raw, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+"/api/token/request", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Poisoned token: valid length, path-structural characters.
	if code := post(map[string]string{
		"token": "12345678/approve", "fingerprint": "fp", "device_name": "evil",
	}); code != http.StatusBadRequest {
		t.Fatalf("slash token: got %d, want 400", code)
	}
	if code := post(map[string]string{
		"token": "abcdefgh%2Fapprove", "fingerprint": "fp", "device_name": "evil",
	}); code != http.StatusBadRequest {
		t.Fatalf("encoded-slash token: got %d, want 400", code)
	}
	// Legit base64url token (43 chars) passes.
	if code := post(map[string]string{
		"token": "AbCdEfGh1234567890_-AbCdEfGh1234567890_-AbCd", "fingerprint": "fp", "device_name": "ok",
	}); code != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200", code)
	}
}

// TestTokenEndpointsRequirePOST: GET-reachable action paths multiply
// delivery vectors; all action endpoints must answer 405 to GET.
func TestTokenEndpointsRequirePOST(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	h := New(db, NewAuth(db), false)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	for _, path := range []string{"/api/token/request", "/api/token/heartbeat", "/api/token/health"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: got %d, want 405", path, code)
		}
	}
	// Action endpoints are auth-gated first (401 unauthenticated); method
	// enforcement is covered post-auth by the poisoned-row test.
}

// TestPeerActionRejectsPoisonedLegacyRows: even if a pre-fix poisoned
// token row exists in the DB, the action router refuses to act on it.
func TestPeerActionRejectsPoisonedLegacyRows(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	// Simulate a legacy poisoned row (registered before the charset gate).
	db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen) VALUES('12345678/approve','fp','pending',datetime('now'),datetime('now'))`)

	auth := NewAuth(db)
	h := New(db, auth, false)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	// Admin session so the request passes auth and reaches the handler.
	if err := auth.EnsureAdmin("admin", "password123"); err != nil {
		t.Fatal(err)
	}
	ok, _ := auth.Login("admin", "password123")
	if !ok {
		t.Fatal("login failed")
	}
	sid := auth.CreateSession("admin")

	req, _ := http.NewRequest("POST", srv.URL+"/admin/api/peers/12345678/approve", nil)
	req.AddCookie(&http.Cookie{Name: "panel_session", Value: sid})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("poisoned legacy row action: got %d, want 400", resp.StatusCode)
	}
	// And the peer must NOT have been approved by the misrouted action.
	var status string
	db.QueryRow(`SELECT status FROM peers WHERE token='12345678/approve'`).Scan(&status)
	if strings.EqualFold(status, "approved") {
		t.Fatal("poisoned row was approved through the path split")
	}
}
