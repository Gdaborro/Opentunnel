package panel

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBootstrapUnauthenticatedPendingCapIsBounded(t *testing.T) {
	db := newTestDB(t)
	seedPendingRows(t, db, unauthenticatedPendingLimit)
	req := registrationRequest{Token: "bootstrap-overflow-123456", Fingerprint: "overflow-fingerprint", SSHPubKey: testKeyLine(t)}
	if _, _, _, err := db.registerBootstrap(t.Context(), req, false); !errors.Is(err, errRegistrationDenied) {
		t.Fatalf("bootstrap pending cap was not enforced: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM peers WHERE token='flood-0001'`); err != nil {
		t.Fatal(err)
	}
	status, _, created, err := db.registerBootstrap(t.Context(), req, false)
	if err != nil || status != "pending" || !created {
		t.Fatalf("bootstrap did not recover after one pending slot opened: %q %v %v", status, created, err)
	}
}

func TestBootstrapRegistrationReadAndAuditFaultCannotEnrollOrApprove(t *testing.T) {
	for _, fault := range []string{"ban-read", "audit-write"} {
		t.Run(fault, func(t *testing.T) {
			db := newTestDB(t)
			key := testKeyLine(t)
			req := registrationRequest{Token: "synthetic-bootstrap-token-12345", Fingerprint: "synthetic-bootstrap", SSHPubKey: key}
			if fault == "ban-read" {
				if _, err := db.Exec(`ALTER TABLE fingerprints_banned RENAME TO unavailable_bans`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := db.Exec(`CREATE TRIGGER deny_registration_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, _, err := db.registerBootstrap(t.Context(), req, true); err == nil {
				t.Fatal("failed policy/audit operation enrolled an automatically approved peer")
			}
			var peers int
			if err := db.QueryRow(`SELECT COUNT(*) FROM peers`).Scan(&peers); err != nil || peers != 0 {
				t.Fatal("failed bootstrap partly created identity", err)
			}
		})
	}
}

func TestAutomatedKickAndPersistentThrottleAreTransactional(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	if _, err := db.Exec(`CREATE TRIGGER deny_auto_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if db.AutoKick(token, "fixture", time.Now().Add(time.Minute)) {
		t.Fatal("auto-kick ignored audit fault")
	}
	p, err := db.AccessPolicy(token)
	if err != nil || p.Status != "approved" {
		t.Fatal("auto-kick partly changed admission", err)
	}
	var winners int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if db.throttleKV("shared-test", time.Hour) {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if winners != 1 {
		t.Fatal("persistent throttle check-then-write race", winners)
	}
}

func TestBootstrapPendingKeyBackfillIsAuditedAndAtomic(t *testing.T) {
	db := newTestDB(t)
	const token = "synthetic-backfill-token-12345"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,ssh_pubkey,status,created_at,last_seen,auth_epoch) VALUES(?,'fixture','','pending',datetime('now'),datetime('now'),'original')`, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER deny_backfill_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.registerBootstrap(t.Context(), registrationRequest{Token: token, Fingerprint: "fixture", SSHPubKey: testKeyLine(t)}, false); err == nil {
		t.Fatal("backfill ignored audit failure")
	}
	if db.SSHPubKey(token) != "" {
		t.Fatal("failed audit left key partly backfilled")
	}
}

func TestBootstrapCannotBypassPoolOrIdentityBan(t *testing.T) {
	db := newTestDB(t)
	key := testKeyLine(t)
	req := registrationRequest{Token: "synthetic-bootstrap-token-12345", Fingerprint: "fixture", SSHPubKey: key}
	if _, err := db.Exec(`INSERT INTO pubkeys_banned(pubkey,reason,banned_at) VALUES(?,'fixture',datetime('now'))`, key); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.registerBootstrap(t.Context(), req, true); err == nil {
		t.Fatal("identity ban bypassed by legacy bootstrap")
	}
	db = newTestDB(t)
	if _, err := db.BindServerPool(syntheticEnrollmentPool, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.registerBootstrap(t.Context(), req, true); err == nil {
		t.Fatal("omitted configured pool context bypassed persisted authority")
	}
}

func TestSentinelModeRequestMalformedOrAuditFaultDoesNotChangePolicy(t *testing.T) {
	db := newTestDB(t)
	db.SetSetting("sentinel_mode", "respond")
	h := New(db, NewAuth(db), false)
	for _, body := range []string{`{"mode":"off","mode":"respond"}`, `{"Mode":"off"}`, `{"mode":"off"} {}`, `null`} {
		w := httptest.NewRecorder()
		h.apiSentinel(w, httptest.NewRequest(http.MethodPost, "/admin/api/sentinel", strings.NewReader(body)))
		if w.Code < 400 || db.Setting("sentinel_mode") != "respond" {
			t.Fatal("malformed mode changed protection")
		}
	}
	if _, err := db.Exec(`CREATE TRIGGER deny_sentinel_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.apiSentinel(w, httptest.NewRequest(http.MethodPost, "/admin/api/sentinel", strings.NewReader(`{"mode":"off"}`)))
	if w.Code != 503 || db.Setting("sentinel_mode") != "respond" {
		t.Fatal("mode/audit committed nonatomically")
	}
}
