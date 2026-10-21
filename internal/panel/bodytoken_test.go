package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// TestTokenStatusAcceptsBodyToken covers the v0.9.22 control-plane change:
// the device token may ride the JSON body (POST) instead of the URL query,
// so TLS-intercepting middleboxes no longer see the credential in the
// request line. The legacy query form must keep working for clients
// predating the change.
func TestTokenStatusAcceptsBodyToken(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	const tok = "bodytoken-test-12345678"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen) VALUES(?, 'fp', 'approved', datetime('now'), datetime('now'))`, tok); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	h := New(db, NewAuth(db), false)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	// Body form (v0.9.22+ clients).
	resp, err := http.Post(srv.URL+"/api/token/status", "application/json",
		bytes.NewReader([]byte(`{"token":"`+tok+`"}`)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if res["status"] != "approved" {
		t.Fatalf("body form: status %q, want approved", res["status"])
	}

	// Legacy query form (older clients during migration).
	resp2, err := http.Get(srv.URL + "/api/token/status?token=" + tok)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var res2 map[string]string
	json.NewDecoder(resp2.Body).Decode(&res2)
	resp2.Body.Close()
	if res2["status"] != "approved" {
		t.Fatalf("query form: status %q, want approved", res2["status"])
	}

	// Unknown token keeps the not-found contract in both forms.
	resp3, err := http.Post(srv.URL+"/api/token/status", "application/json",
		bytes.NewReader([]byte(`{"token":"no-such-token"}`)))
	if err != nil {
		t.Fatalf("post unknown: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token: status %d, want 404", resp3.StatusCode)
	}
}
