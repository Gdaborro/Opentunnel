package panel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHReconcileRetainsRevocationAcrossDeletedRowsAndMissingFiles(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	key, operator := testKeyLine(t), testKeyLine(t)
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=? WHERE token=?`, key, token); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if _, err := db.ReconcileSSH(path, "127.0.0.1:8081"); err != nil {
		t.Fatal("missing enabled inventory not recreated", err)
	}
	if err := os.WriteFile(path, []byte(key+" device\n"+operator+" operator\n# preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Simulate the reaper, not a handler hook. The SQL trigger saves ownership.
	if _, err := db.Exec(`DELETE FROM peers WHERE token=?`, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReconcileSSH(path, "127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(raw), key) || !strings.Contains(string(raw), operator+" operator") || !strings.Contains(string(raw), "# preserve") {
		t.Fatal("lost revocation/ownership boundary", err)
	}
	// A fault must leave the existing file byte-for-byte untouched.
	if _, err := db.Exec(`ALTER TABLE managed_ssh_keys RENAME TO unavailable_keys`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReconcileSSH(path, "127.0.0.1:8081"); err == nil {
		t.Fatal("inventory fault reported success")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("SQL failure cleared operator inventory")
	}
}

func TestSSHFailedApplyReportsPendingAndRetriesDurably(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	key := testKeyLine(t)
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=? WHERE token=?`, key, token); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "missing-parent", "authorized_keys")
	h := New(db, NewAuth(db), false).WithSSHReconciler(func() error { _, err := db.ReconcileSSH(path, "127.0.0.1:8081"); return err })
	w := httptest.NewRecorder()
	h.apiPeerAction(w, httptest.NewRequest(http.MethodPost, "/admin/api/peers/"+token+"/ban", strings.NewReader(`{"reason":"fixture"}`)))
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"ssh_reconcile_pending":true`) {
		t.Fatal("failed SSH apply claimed complete", w.Code)
	}
	p, err := db.AccessPolicy(token)
	if err != nil || p.Status != "banned" {
		t.Fatal("SSH failure undid admission revocation", err)
	}
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(key+" previously authorized\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReconcileSSH(path, "127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), key) {
		t.Fatal("missed hook lost durable revocation")
	}
}

func TestRekeyAuditFailureLeavesIdentityAndSSHUnchanged(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	old, replacement := testKeyLine(t), testKeyLine(t)
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=? WHERE token=?`, old, token); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authorized_keys")
	if _, err := db.ReconcileSSH(path, "127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if _, err := db.Exec(`CREATE TRIGGER deny_rekey_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture fault'); END`); err != nil {
		t.Fatal(err)
	}
	h := New(db, NewAuth(db), false).WithSSHReconciler(func() error { _, err := db.ReconcileSSH(path, "127.0.0.1:8081"); return err })
	w := httptest.NewRecorder()
	body := `{"ssh_pubkey":"` + replacement + `","expected_ssh_pubkey":"` + old + `","confirm":true}`
	h.apiPeerAction(w, httptest.NewRequest(http.MethodPost, "/admin/api/peers/"+token+"/rekey", strings.NewReader(body)))
	p, err := db.AccessPolicy(token)
	after, _ := os.ReadFile(path)
	if w.Code < 400 || err != nil || p.PublicKey != old || p.Generation != "epoch-a" || string(after) != string(raw) {
		t.Fatal("failed rekey partially mutated identity or SSH", w.Code, err)
	}
}

func TestStrictPeerActionsRejectMalformedBodiesBeforeAnyMutation(t *testing.T) {
	for _, action := range []string{"approve", "ban", "kick", "unban", "expire", "delete", "reset", "limits", "rekey"} {
		t.Run(action, func(t *testing.T) {
			db := newTestDB(t)
			token := accessPeer(t, db)
			key := testKeyLine(t)
			if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=? WHERE token=?`, key, token); err != nil {
				t.Fatal(err)
			}
			h := New(db, NewAuth(db), false)
			for _, body := range []string{`null`, `{broken`, `{} {}`, `{"reason":"x","reason":"y"}`, `{"unknown":true}`} {
				w := httptest.NewRecorder()
				h.apiPeerAction(w, httptest.NewRequest(http.MethodPost, "/admin/api/peers/"+token+"/"+action, strings.NewReader(body)))
				p, err := db.AccessPolicy(token)
				if w.Code < 400 || err != nil || p.PublicKey != key || p.Status != "approved" || p.Generation != "epoch-a" {
					t.Fatal("malformed action changed admission", body, w.Code, err)
				}
			}
		})
	}
}
