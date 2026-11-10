package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func postRegister(t *testing.T, baseURL, token, fp, name, pub string) map[string]string {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{
		"token": token, "fingerprint": fp, "device_name": name, "ssh_pubkey": pub,
	})
	resp, err := http.Post(baseURL+"/api/token/request", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// TestRegistrationKeyRotation: a different key presented by an approved
// device revokes the old authorized_keys line, stores the new key and
// forces re-approval; re-posting the same new key does not churn alerts;
// approval installs the new line. Regression test for the 2026-11-05
// incident: the old COALESCE-only update silently kept a key the device
// no longer had, so the ssh tier failed on every attempt — forever, with
// no panel signal.
func TestRegistrationKeyRotation(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	keyA := testKeyLine(t)
	keyB := testKeyLine(t)
	if _, err := UpsertAuthorizedKey(akPath, keyA, "127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}

	h := New(db, NewAuth(db), false)
	h.OnApprove = func(tok string) {
		if _, err := UpsertAuthorizedKey(akPath, h.SSHKeyPath(tok), "127.0.0.1:8081"); err != nil {
			t.Errorf("approve hook: %v", err)
		}
	}
	h.OnRevoke = func(tok string) {
		if _, err := RemoveAuthorizedKey(akPath, h.SSHKeyPath(tok)); err != nil {
			t.Errorf("revoke hook: %v", err)
		}
	}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	const tok = "rotation-test-token-123456"
	const dev = "rotation-device"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen)
		VALUES(?, 'fp', ?, ?, 'approved', datetime('now'), datetime('now'))`, tok, dev, keyA); err != nil {
		t.Fatal(err)
	}

	// Same key: liveness only, still approved, no churn.
	if res := postRegister(t, srv.URL, tok, "fp", dev, keyA); res["status"] != "approved" {
		t.Fatalf("same-key status = %q, want approved", res["status"])
	}

	// New key: pending, old line revoked, new key stored but NOT installed.
	if res := postRegister(t, srv.URL, tok, "fp", dev, keyB); res["status"] != "pending" {
		t.Fatalf("rotated status = %q, want pending", res["status"])
	}
	raw, _ := os.ReadFile(akPath)
	if bytes.Contains(raw, []byte(keyA)) {
		t.Fatal("old key must be revoked on rotation")
	}
	if bytes.Contains(raw, []byte(keyB)) {
		t.Fatal("new key must not be installed before approval")
	}
	if got := h.SSHKeyPath(tok); got != keyB {
		t.Fatalf("stored key = %q, want the new key", got)
	}

	// Re-posting the same new key must not rotate or alert again.
	var alerts1 int
	db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alerts1)
	if res := postRegister(t, srv.URL, tok, "fp", dev, keyB); res["status"] != "pending" {
		t.Fatalf("repeat status = %q, want pending", res["status"])
	}
	var alerts2 int
	db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alerts2)
	if alerts2 != alerts1 {
		t.Fatalf("repeat registration re-alerted: %d -> %d", alerts1, alerts2)
	}

	// Approval installs the new line, exactly once.
	db.Exec(`UPDATE peers SET status='approved' WHERE token=?`, tok)
	h.OnApprove(tok)
	raw, _ = os.ReadFile(akPath)
	if !bytes.Contains(raw, []byte(keyB)) {
		t.Fatal("approved key was not installed")
	}
	if bytes.Count(raw, []byte(keyB)) != 1 {
		t.Fatalf("new key must appear exactly once: %s", raw)
	}
}

// TestRegistrationKeyBackfill: a row without a stored key accepts and
// installs the device's announced key when it is already approved (a
// repair, not a rotation).
func TestRegistrationKeyBackfill(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	key := testKeyLine(t)
	h := New(db, NewAuth(db), false)
	h.OnApprove = func(tok string) {
		if _, err := UpsertAuthorizedKey(akPath, h.SSHKeyPath(tok), "127.0.0.1:8081"); err != nil {
			t.Errorf("approve hook: %v", err)
		}
	}
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()

	const tok = "backfill-test-token-123456"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen)
		VALUES(?, 'fp', 'backfill-device', '', 'approved', datetime('now'), datetime('now'))`, tok); err != nil {
		t.Fatal(err)
	}
	if res := postRegister(t, srv.URL, tok, "fp", "backfill-device", key); res["status"] != "approved" {
		t.Fatalf("backfill status = %q, want approved", res["status"])
	}
	raw, _ := os.ReadFile(akPath)
	if !bytes.Contains(raw, []byte(key)) {
		t.Fatal("backfilled key was not installed")
	}
}
