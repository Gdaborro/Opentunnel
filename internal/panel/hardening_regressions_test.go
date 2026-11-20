package panel

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoginAdmissionCountsOutstandingWork(t *testing.T) {
	a := NewAuth(nil)
	const source = "192.0.2.5"
	attempts := make([]*loginAttempt, 0, loginMaxFails)
	for range loginMaxFails {
		attempt, ok := a.beginLogin(source)
		if !ok {
			t.Fatal("early admission failure")
		}
		attempts = append(attempts, attempt)
	}
	if _, ok := a.beginLogin(source); ok {
		t.Fatal("parallel requests bypassed login threshold")
	}
	attempts[0].finish(true, false)
	attempts[0].finish(false, true)
	a.lmu.Lock()
	inflight := a.fails[source].inflight
	a.lmu.Unlock()
	if inflight != loginMaxFails-1 {
		t.Fatal("success dropped another in-flight reservation", inflight)
	}
	for _, attempt := range attempts[1:] {
		attempt.finish(false, true)
	}
	attempt, ok := a.beginLogin(source)
	if !ok {
		t.Fatal("successful login left permanent false lockout")
	}
	attempt.finish(false, true)
	if !a.LoginLocked(source) {
		t.Fatal("completed failures did not lock source")
	}
}

func TestPasswordBudgetIsSharedAndNonqueued(t *testing.T) {
	releases := []func(){}
	for range maxPasswordWork {
		release, err := passwordWork()
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	if _, err := NewAuth(nil).Login("synthetic-user", "synthetic-password"); !errors.Is(err, ErrAuthenticationBusy) {
		t.Fatal("admin work bypassed budget", err)
	}
	if _, err := newTestDB(t).verifyEnrollmentAccount(t.Context(), "synthetic-user", "synthetic-password"); !errors.Is(err, ErrAuthenticationBusy) {
		t.Fatal("enrollment bypassed shared budget", err)
	}
}

func TestConcurrentAdminLoginsReserveBeforeBcrypt(t *testing.T) {
	db := newTestDB(t)
	auth := NewAuth(db)
	if err := auth.EnsureAdmin("synthetic-admin", "Synthetic-hardening-password-only"); err != nil {
		t.Fatal(err)
	}
	h := New(db, auth, false)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	var rejected atomic.Int32
	for range 12 {
		wg.Go(func() {
			<-gate
			r := httptest.NewRequest(http.MethodPost, "/admin/api/login", strings.NewReader(`{"username":"synthetic-admin","password":"wrong-synthetic-password"}`))
			r.RemoteAddr = "192.0.2.44:40000"
			w := httptest.NewRecorder()
			h.apiLogin(w, r)
			if w.Code == http.StatusUnauthorized {
				rejected.Add(1)
			} else if w.Code != 429 {
				t.Errorf("unexpected admission status %d", w.Code)
			}
		})
	}
	close(gate)
	wg.Wait()
	if rejected.Load() > loginMaxFails {
		t.Fatal("too many attempts reached password verification", rejected.Load())
	}
}

func TestLoginSourceMemoryIsHardBounded(t *testing.T) {
	a := NewAuth(nil)
	for i := range maxLoginSources + 100 {
		attempt, ok := a.beginLogin(fmt.Sprintf("192.0.%d.%d", i/256, i%256))
		if ok {
			attempt.finish(false, true)
		}
	}
	if len(a.fails) > maxLoginSources {
		t.Fatal("login source map exceeded hard limit")
	}
}

func TestFilteringReadFailureDeniesAllTargetsAndPreservesLastCompletePolicy(t *testing.T) {
	db := newTestDB(t)
	if err := db.BlocklistAction(t.Context(), "POST", "blocked.example", "synthetic block", false); err != nil {
		t.Fatal(err)
	}
	if blocked, reason, err := db.CheckBlocked("sub.blocked.example"); err != nil || !blocked || reason != "synthetic block" {
		t.Fatal(blocked, reason, err)
	}
	if _, err := db.Exec(`ALTER TABLE blocklist RENAME TO unavailable_blocklist`); err != nil {
		t.Fatal(err)
	}
	db.invalidateBlockCache()
	for _, domain := range []string{"blocked.example", "previously-allowed.example"} {
		if blocked, _, err := db.CheckBlocked(domain); err == nil || !blocked {
			t.Fatal("filter policy failed open", domain, err)
		}
		if !db.IsBlocked(domain) {
			t.Fatal("legacy boolean policy failed open")
		}
	}
	db.block.mu.Lock()
	rules := append([]blockRule(nil), db.block.rules...)
	db.block.mu.Unlock()
	if len(rules) != 1 || rules[0].domain != "blocked.example" {
		t.Fatal("error replaced last complete policy")
	}
}

func TestBlocklistMalformedOrUnconfirmedClearDoesNotChangePolicy(t *testing.T) {
	db := newTestDB(t)
	h := New(db, NewAuth(db), false)
	if err := db.BlocklistAction(t.Context(), "POST", "blocked.example", "synthetic", false); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{broken`, `null`, `{}`, `{"clear":true}`, `{"clear":true,"confirm_clear":false}`, `{"domain":"blocked.example"} {}`, `{"domain":"blocked.example","domain":"blocked.example"}`} {
		w := httptest.NewRecorder()
		h.apiBlocklist(w, httptest.NewRequest(http.MethodDelete, "/admin/api/blocklist", strings.NewReader(raw)))
		var count int
		_ = db.QueryRow(`SELECT COUNT(*) FROM blocklist`).Scan(&count)
		if w.Code < 400 || count != 1 {
			t.Fatal("malformed mutation changed policy", w.Code, count)
		}
	}
	w := httptest.NewRecorder()
	h.apiBlocklist(w, httptest.NewRequest(http.MethodDelete, "/admin/api/blocklist", strings.NewReader(`{"clear":true,"confirm_clear":true}`)))
	if w.Code != 200 {
		t.Fatal("confirmed clear refused", w.Code)
	}
}

func TestBlocklistAuditFailureRollsBackMutation(t *testing.T) {
	db := newTestDB(t)
	if err := db.BlocklistAction(t.Context(), "POST", "blocked.example", "synthetic", false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER deny_block_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'synthetic audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.BlocklistAction(t.Context(), "DELETE", "blocked.example", "", false); err == nil {
		t.Fatal("failed audit reported successful mutation")
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM blocklist`).Scan(&count)
	if count != 1 {
		t.Fatal("partial delete committed")
	}
}

func TestManagedSSHReconcileHardensAndRevokesButPreservesOtherEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	desired, revoked, unrelated := testKeyLine(t), testKeyLine(t), testKeyLine(t)
	raw := desired + " historic unmanaged options\n" + desired + " duplicate\n" + revoked + " revoked\n" + unrelated + " operator-owned\n# unrelated operator comment\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileManagedAuthorizedKeys(path, "127.0.0.1:8081", []string{desired}, []string{revoked}); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(result), desired) != 1 || !strings.Contains(string(result), CanonicalAuthorizedKeyLine(desired, "127.0.0.1:8081")) || strings.Contains(string(result), revoked) || !strings.Contains(string(result), unrelated+" operator-owned") || !strings.Contains(string(result), "# unrelated operator comment") {
		t.Fatal("incorrect managed/unmanaged reconcile boundaries")
	}
	before := string(result)
	if _, err := ReconcileManagedAuthorizedKeys(path, `127.0.0.1:8081" malicious`, []string{desired}, nil); err == nil {
		t.Fatal("permitopen injection accepted")
	}
	if result, _ := os.ReadFile(path); string(result) != before {
		t.Fatal("invalid target changed key policy")
	}
}

func TestCheckedV5PersistenceRejectsWriteFailureOrGenerationChange(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	key := testKeyLine(t)
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=? WHERE token=?`, key, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER deny_upgrade BEFORE UPDATE OF v5_seen ON peers BEGIN SELECT RAISE(ABORT,'synthetic latch failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.CommitV5(token, "epoch-a", key); err == nil {
		t.Fatal("ignored upgrade persistence failure")
	}
	if db.V5Seen(token) {
		t.Fatal("faulty latch reported durable")
	}
	if _, err := db.Exec(`DROP TRIGGER deny_upgrade`); err != nil {
		t.Fatal(err)
	}
	if err := db.CommitV5(token, "old-generation", key); err == nil {
		t.Fatal("old session latched new identity")
	}
	if err := db.CommitV5(token, "epoch-a", key); err != nil {
		t.Fatal(err)
	}
	if !db.V5Seen(token) {
		t.Fatal("verified upgrade did not persist")
	}
}

func TestAuthBusyDoesNotAccumulateBadPasswordFailures(t *testing.T) {
	a := NewAuth(nil)
	for range 20 {
		attempt, ok := a.beginLogin("192.0.2.77")
		if !ok {
			t.Fatal("busy verification caused false lockout")
		}
		attempt.finish(false, false)
	}
	if a.LoginLocked("192.0.2.77") {
		t.Fatal("transient busy state labeled incorrect password")
	}
	a.loginSweep = time.Now().Add(-2 * time.Minute)
}
