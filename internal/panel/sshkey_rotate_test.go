package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
	out := map[string]string{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	out["http_status"] = strconv.Itoa(resp.StatusCode)
	return out
}

// Public bootstrap requests must not replace an active identity. An admin
// explicitly verifies the new key, revokes the old one, and requests approval.
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

	// A token holder without the original private key gets a conflict,
	// not a way to disconnect or overwrite the legitimate device.
	if res := postRegister(t, srv.URL, tok, "fp", dev, keyB); res["http_status"] != "409" {
		t.Fatalf("unauthenticated replacement status = %q, want 409", res["http_status"])
	}
	raw, _ := os.ReadFile(akPath)
	if !bytes.Contains(raw, []byte(keyA)) {
		t.Fatal("public conflict must leave the legitimate key authorized")
	}
	if bytes.Contains(raw, []byte(keyB)) {
		t.Fatal("new key must not be installed before approval")
	}
	if got := h.SSHKeyPath(tok); got != keyA {
		t.Fatal("public conflict replaced the stored identity")
	}

	// Re-posting the same new key must not rotate or alert again.
	var alerts1 int
	db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alerts1)
	h.autoApprove = true // an auto-approve policy must not permit takeover either
	if res := postRegister(t, srv.URL, tok, "fp", dev, keyB); res["http_status"] != "409" {
		t.Fatalf("repeat status = %q, want 409", res["http_status"])
	}
	var alerts2 int
	db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alerts2)
	if alerts2 != alerts1 {
		t.Fatalf("repeat registration re-alerted: %d -> %d", alerts1, alerts2)
	}
	if _, err := db.Exec(`INSERT INTO admins(username,password_hash) VALUES('fixture','not-a-login-hash')`); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"ssh_pubkey": keyB, "expected_ssh_pubkey": keyA, "confirm": true})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/peers/"+tok+"/rekey", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "panel_session", Value: h.auth.CreateSession("fixture")})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || h.SSHKeyPath(tok) != keyB {
		t.Fatal("authenticated administrative replacement did not succeed")
	}
	var state string
	db.QueryRow(`SELECT status FROM peers WHERE token=?`, tok).Scan(&state)
	if state != "pending" {
		t.Fatal("admin rekey must require approval, even with auto-approve enabled")
	}
	db.SetAutoAccept(60)
	if res := postRegister(t, srv.URL, tok, "fp", dev, keyB); res["status"] != "pending" {
		t.Fatal("public registration auto-approved an administrator rekey during the window")
	}
	raw, _ = os.ReadFile(akPath)
	if bytes.Contains(raw, []byte(keyA)) || bytes.Contains(raw, []byte(keyB)) {
		t.Fatal("rekey must revoke the old key without authorizing the new one yet")
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

// Only a still-pending bootstrap row can backfill an initially absent key.
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
		VALUES(?, 'fp', 'backfill-device', '', 'pending', datetime('now'), datetime('now'))`, tok); err != nil {
		t.Fatal(err)
	}
	if res := postRegister(t, srv.URL, tok, "fp", "backfill-device", key); res["status"] != "pending" {
		t.Fatalf("backfill status = %q, want pending", res["status"])
	}
	db.Exec(`UPDATE peers SET status='approved' WHERE token=?`, tok)
	h.OnApprove(tok)
	raw, _ := os.ReadFile(akPath)
	if !bytes.Contains(raw, []byte(key)) {
		t.Fatal("backfilled key was not installed")
	}
}
