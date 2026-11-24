package panel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

const syntheticEnrollmentPool = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const syntheticEnrollmentPassword = "Synthetic-enrollment-password-only"

func enrollmentFixture(t *testing.T, login bool) (*DB, *Handler) {
	t.Helper()
	db := newTestDB(t)
	h, err := New(db, NewAuth(db), true).WithServerPool(syntheticEnrollmentPool, login)
	if err != nil {
		t.Fatal(err)
	}
	return db, h
}

func enrollmentIdentity(t *testing.T, suffix string) (enrollmentRequest, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := ssh.NewPublicKey(pub)
	return enrollmentRequest{PoolID: syntheticEnrollmentPool, Token: "synthetic-enrollment-token-" + suffix, Fingerprint: "synthetic-fingerprint-" + suffix, DeviceName: "synthetic device", SSHPubKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))}, key
}

func enrollmentHTTP(req enrollmentRequest, key ed25519.PrivateKey, nonce string) (*http.Request, []byte) {
	raw, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "https://entry.example/api/token/request", bytes.NewReader(raw))
	at := strconv.FormatInt(time.Now().Unix(), 10)
	if nonce == "" {
		nonce = base64.RawURLEncoding.EncodeToString(protocol.RandomSalt())
	}
	r.Header.Set("X-Otu-Time", at)
	r.Header.Set("X-Otu-Nonce", nonce)
	r.Header.Set("X-Otu-Proof", base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.HTTPProofMsg(r.Method, r.URL.EscapedPath(), at, nonce, raw))))
	return r, raw
}

func sendEnrollment(t *testing.T, h *Handler, req enrollmentRequest, key ed25519.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	r, _ := enrollmentHTTP(req, key, "")
	w := httptest.NewRecorder()
	h.enrollPool(w, r)
	return w
}

func createSyntheticEnrollmentAccount(t *testing.T, db *DB, max int) *verifiedEnrollmentAccount {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(syntheticEnrollmentPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.setEnrollmentAccount(t.Context(), "synthetic-user", string(hash), nil, &max); err != nil {
		t.Fatal(err)
	}
	account, err := db.verifyEnrollmentAccount(t.Context(), "synthetic-user", syntheticEnrollmentPassword)
	if err != nil || account == nil {
		t.Fatal("fixture account unavailable", err)
	}
	return account
}

func seedPendingRows(t *testing.T, db *DB, count int) {
	t.Helper()
	_, err := db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?)
		INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen,ssh_pubkey,auth_epoch)
		SELECT printf('flood-%04d',x),'flood-fingerprint','flood-device','pending',datetime('now'),datetime('now'),'','epoch' FROM n`, count)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnauthenticatedPendingCapIsBoundedAndRecoverable(t *testing.T) {
	db, _ := enrollmentFixture(t, false)
	seedPendingRows(t, db, unauthenticatedPendingLimit)
	req, _ := enrollmentIdentity(t, "overflow")
	if _, _, err := db.enrollPool(t.Context(), req, false, nil); !errors.Is(err, errEnrollmentDenied) {
		t.Fatalf("unauthenticated pending cap was not enforced: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM peers WHERE token='flood-0001'`); err != nil {
		t.Fatal(err)
	}
	status, created, err := db.enrollPool(t.Context(), req, false, nil)
	if err != nil || status != "pending" || !created {
		t.Fatalf("freeing one pending slot did not restore bounded enrollment: %q %v %v", status, created, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='pending'`).Scan(&count); err != nil || count != unauthenticatedPendingLimit {
		t.Fatalf("unexpected pending count after recovery: %d %v", count, err)
	}
}

func TestAccountPendingDoesNotConsumeUnauthenticatedBudget(t *testing.T) {
	db, _ := enrollmentFixture(t, true)
	account := createSyntheticEnrollmentAccount(t, db, 1)
	seedPendingRows(t, db, unauthenticatedPendingLimit)
	req, _ := enrollmentIdentity(t, "account-backed")
	status, created, err := db.enrollPool(t.Context(), req, true, account)
	if err != nil || status != "pending" || !created {
		t.Fatalf("account-backed enrollment was blocked by unauthenticated rows: %q %v %v", status, created, err)
	}
}

func TestBootstrapApprovedRegistrationDoesNotUsePendingBudget(t *testing.T) {
	db := newTestDB(t)
	seedPendingRows(t, db, unauthenticatedPendingLimit)
	req := registrationRequest{Token: "bootstrap-approved-123456", Fingerprint: "approved-fingerprint", SSHPubKey: testKeyLine(t)}
	status, _, created, err := db.registerBootstrap(t.Context(), req, true)
	if err != nil || status != "approved" || !created {
		t.Fatalf("explicitly approved bootstrap was blocked by pending capacity: %q %v %v", status, created, err)
	}
}

func TestUnauthenticatedPendingCapConcurrentBoundary(t *testing.T) {
	db, _ := enrollmentFixture(t, false)
	seedPendingRows(t, db, unauthenticatedPendingLimit-1)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, suffix := range []string{"boundary-a", "boundary-b"} {
		req, _ := enrollmentIdentity(t, suffix)
		wg.Go(func() { _, _, err := db.enrollPool(context.Background(), req, false, nil); errs <- err })
	}
	wg.Wait()
	close(errs)
	var success, denied int
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, errEnrollmentDenied) {
			denied++
		} else {
			t.Fatalf("unexpected concurrent enrollment error: %v", err)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("cap boundary allowed an overshoot or wrong failure: success=%d denied=%d", success, denied)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM peers WHERE status='pending'`).Scan(&count); err != nil || count != unauthenticatedPendingLimit {
		t.Fatalf("concurrent cap committed the wrong pending total: %d %v", count, err)
	}
}

func TestPoolLoginEnrollsButNeverApproves(t *testing.T) {
	db, h := enrollmentFixture(t, true)
	createSyntheticEnrollmentAccount(t, db, 5)
	db.SetSetting("auto_accept_until", time.Now().Add(time.Hour).UTC().Format("2006-01-02 15:04:05"))
	req, key := enrollmentIdentity(t, "login")
	if w := sendEnrollment(t, h, req, key); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing login: %d %s", w.Code, w.Body.String())
	}
	if db.KnownPeer(req.Token) {
		t.Fatal("login-free request created a protected enrollment")
	}
	req.Username, req.Password = "synthetic-user", syntheticEnrollmentPassword
	w := sendEnrollment(t, h, req, key)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	p, err := db.AccessPolicy(req.Token)
	if err != nil || p.Status != "pending" || !p.Enrolled {
		t.Fatal("login bypassed approval", p, err)
	}
	if _, err := db.ReserveTraffic(t.Context(), req.Token, p.Generation, "", false, 10); err == nil {
		t.Fatal("pending login admitted traffic")
	}
	if err := db.PeerStateAction(req.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	p, err = db.AccessPolicy(req.Token)
	if err != nil || p.Status != "approved" {
		t.Fatal(p, err)
	}
	if _, err := db.ReserveTraffic(t.Context(), req.Token, p.Generation, "", false, 10); err != nil {
		t.Fatal("approved account could not reserve traffic", err)
	}
	req.Username, req.Password = "", ""
	if w := sendEnrollment(t, h, req, key); w.Code != http.StatusOK {
		t.Fatal("subsequent key-auth enrollment requested password", w.Code)
	}
	var plain, stored string
	_ = db.QueryRow(`SELECT password_hash FROM enrollment_accounts WHERE username='synthetic-user'`).Scan(&stored)
	_ = db.QueryRow(`SELECT COALESCE(group_concat(detail),'') FROM events`).Scan(&plain)
	if stored == syntheticEnrollmentPassword || strings.Contains(plain, syntheticEnrollmentPassword) {
		t.Fatal("plaintext password persisted")
	}
}

func TestPoolEnrollmentAccountsCannotLogInAsAdmins(t *testing.T) {
	db, h := enrollmentFixture(t, true)
	createSyntheticEnrollmentAccount(t, db, 5)
	if ok, err := h.auth.Login("synthetic-user", syntheticEnrollmentPassword); err != nil || ok {
		t.Fatal("enrollment account obtained administrator authentication", err)
	}
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("Synthetic-admin-password-only"), bcrypt.MinCost)
	if _, err := db.Exec(`INSERT INTO admins(username,password_hash) VALUES('synthetic-admin',?)`, string(adminHash)); err != nil {
		t.Fatal(err)
	}
	req, key := enrollmentIdentity(t, "admin")
	req.Username, req.Password = "synthetic-admin", "Synthetic-admin-password-only"
	if w := sendEnrollment(t, h, req, key); w.Code != http.StatusUnauthorized {
		t.Fatal("admin account used for enrollment", w.Code)
	}
	if db.KnownPeer(req.Token) {
		t.Fatal("admin login created peer")
	}
	r := httptest.NewRequest(http.MethodGet, "/admin/api/enrollment-accounts", nil)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Fatal("account inventory exposed without an admin session")
	}
}

func TestPoolRequiresSignedEnrollmentBeforeApprovalAndRekey(t *testing.T) {
	db, h := enrollmentFixture(t, false)
	req, key := enrollmentIdentity(t, "legacy")
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,ssh_pubkey,status,created_at,last_seen,auth_epoch) VALUES(?,?,?,'approved',datetime('now'),datetime('now'),'old-generation')`, req.Token, req.Fingerprint, req.SSHPubKey); err != nil {
		t.Fatal(err)
	}
	if p, err := db.AccessPolicy(req.Token); err != nil || p.Status != "pending" {
		t.Fatal("legacy approved row bypassed pool enrollment", p, err)
	}
	if err := db.PeerStateAction(req.Token, "approve", "", ""); err == nil {
		t.Fatal("administrator action bypassed enrollment")
	}
	if w := sendEnrollment(t, h, req, key); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	p, _ := db.AccessPolicy(req.Token)
	if p.Status != "pending" || p.Generation == "old-generation" {
		t.Fatal("enrollment inherited legacy approval")
	}
	if err := db.PeerStateAction(req.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	replacement, replacementKey := enrollmentIdentity(t, "replacement")
	replacement.Token, replacement.Fingerprint = req.Token, req.Fingerprint
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=?,status='pending',approval_required=1,auth_epoch='new-generation' WHERE token=?`, replacement.SSHPubKey, req.Token); err != nil {
		t.Fatal(err)
	}
	if err := db.PeerStateAction(req.Token, "approve", "", ""); err == nil {
		t.Fatal("old enrollment authorized a replacement key")
	}
	if w := sendEnrollment(t, h, replacement, replacementKey); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := db.PeerStateAction(req.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestPoolEnrollmentProofAndReplay(t *testing.T) {
	db, h := enrollmentFixture(t, false)
	req, key := enrollmentIdentity(t, "proof")
	r, raw := enrollmentHTTP(req, key, "")
	at, nonce, proof := r.Header.Get("X-Otu-Time"), r.Header.Get("X-Otu-Nonce"), r.Header.Get("X-Otu-Proof")
	w := httptest.NewRecorder()
	h.enrollPool(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodPost, "https://entry.example/api/token/request", bytes.NewReader(raw))
	r.Header.Set("X-Otu-Time", at)
	r.Header.Set("X-Otu-Nonce", nonce)
	r.Header.Set("X-Otu-Proof", proof)
	w = httptest.NewRecorder()
	h.enrollPool(w, r)
	if w.Code != 403 {
		t.Fatal("same proof replayed", w.Code)
	}
	restarted, err := New(db, NewAuth(db), false).WithServerPool(syntheticEnrollmentPool, false)
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodPost, "https://entry.example/api/token/request", bytes.NewReader(raw))
	r.Header.Set("X-Otu-Time", at)
	r.Header.Set("X-Otu-Nonce", nonce)
	r.Header.Set("X-Otu-Proof", proof)
	w = httptest.NewRecorder()
	restarted.enrollPool(w, r)
	if w.Code != 403 {
		t.Fatal("panel restart reopened signed enrollment replay", w.Code)
	}
	other, _ := enrollmentIdentity(t, "substitution")
	other.Token, other.Fingerprint = req.Token, req.Fingerprint
	if w := sendEnrollment(t, h, other, key); w.Code != 403 {
		t.Fatal("substituted key without possession accepted", w.Code)
	}
	if pub := db.SSHPubKey(req.Token); pub != req.SSHPubKey {
		t.Fatal("stored key replaced by unauthenticated proof")
	}
	r, raw = enrollmentHTTP(req, key, "")
	old := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	r.Header.Set("X-Otu-Time", old)
	r.Header.Set("X-Otu-Proof", base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.HTTPProofMsg(r.Method, r.URL.EscapedPath(), old, r.Header.Get("X-Otu-Nonce"), raw))))
	w = httptest.NewRecorder()
	h.enrollPool(w, r)
	if w.Code != 403 {
		t.Fatal("expired signed proof accepted", w.Code)
	}
}

func TestPoolEnrollmentIdentityConflictAlertsWithoutMutation(t *testing.T) {
	db, h := enrollmentFixture(t, false)
	original, _ := enrollmentIdentity(t, "original")
	if _, _, err := db.enrollPool(t.Context(), original, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE peers SET status='approved',approval_required=0,auth_epoch='original-generation' WHERE token=?`, original.Token); err != nil {
		t.Fatal(err)
	}
	before := identityStateSnapshot(t, db)
	var enrolledPool, enrolledKey string
	if err := db.QueryRow(`SELECT pool_id,public_key FROM peer_enrollments WHERE token=?`, original.Token).Scan(&enrolledPool, &enrolledKey); err != nil {
		t.Fatal(err)
	}

	conflict, conflictKey := enrollmentIdentity(t, "conflict")
	conflict.Token = original.Token
	for i := 0; i < 2; i++ {
		r, _ := enrollmentHTTP(conflict, conflictKey, "")
		r.RemoteAddr = "203.0.113.87:40000"
		w := httptest.NewRecorder()
		h.enrollPool(w, r)
		if w.Code != http.StatusConflict {
			t.Fatalf("identity conflict status = %d, want 409: %s", w.Code, w.Body.String())
		}
	}
	var severity, kind, message string
	if err := db.QueryRow(`SELECT severity,kind,message FROM alerts WHERE kind='security'`).Scan(&severity, &kind, &message); err != nil {
		t.Fatalf("signed-pool conflict alert: %v", err)
	}
	for _, want := range []string{"203.0.113.87", "ssh_pubkey", "fingerprint", "stored identity preserved", "possible clone, reinstall, or spoof"} {
		if !strings.Contains(message, want) {
			t.Fatalf("conflict alert missing %q: %s", want, message)
		}
	}
	if severity != "warning" || kind != "security" {
		t.Fatalf("unexpected conflict alert classification: %s %s", severity, kind)
	}
	var securityAlerts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind='security'`).Scan(&securityAlerts); err != nil || securityAlerts != 1 {
		t.Fatalf("conflict alert was not throttled: %d err=%v", securityAlerts, err)
	}
	if after := identityStateSnapshot(t, db); after != before {
		t.Fatal("identity conflict changed the original peer, keys, status, epoch, managed keys, or bans")
	}
	var afterPool, afterKey string
	if err := db.QueryRow(`SELECT pool_id,public_key FROM peer_enrollments WHERE token=?`, original.Token).Scan(&afterPool, &afterKey); err != nil || afterPool != enrolledPool || afterKey != enrolledKey {
		t.Fatalf("signed enrollment binding changed: %q %q err=%v", afterPool, afterKey, err)
	}
}

func TestPoolEnrollmentAccountDisableAndQuotaAreTransactional(t *testing.T) {
	db, _ := enrollmentFixture(t, true)
	account := createSyntheticEnrollmentAccount(t, db, 1)
	req, _ := enrollmentIdentity(t, "first")
	if _, _, err := db.enrollPool(t.Context(), req, true, account); err != nil {
		t.Fatal(err)
	}
	if err := db.PeerStateAction(req.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	no := false
	if err := db.setEnrollmentAccount(t.Context(), account.username, "", &no, nil); err != nil {
		t.Fatal(err)
	}
	second, _ := enrollmentIdentity(t, "second")
	if _, _, err := db.enrollPool(t.Context(), second, true, account); !errors.Is(err, errEnrollmentDenied) {
		t.Fatal("disabled account enrolled using a stale bcrypt result", err)
	}
	if p, err := db.AccessPolicy(req.Token); err != nil || p.Status != "approved" {
		t.Fatal("account disable revoked existing device implicitly", p, err)
	}
	if _, _, err := db.enrollPool(t.Context(), req, true, nil); err != nil {
		t.Fatal("existing device required disabled account password", err)
	}
	yes := true
	if err := db.setEnrollmentAccount(t.Context(), account.username, "", &yes, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.enrollPool(t.Context(), second, true, account); !errors.Is(err, errEnrollmentDenied) {
		t.Fatal("account device quota exceeded", err)
	}
	if db.KnownPeer(second.Token) {
		t.Fatal("denied transaction left a pending peer")
	}
	if err := db.PeerStateAction(req.Token, "ban", "synthetic ban", "permanent"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.enrollPool(t.Context(), req, true, nil); !errors.Is(err, errEnrollmentDenied) {
		t.Fatal("banned device reenrolled", err)
	}
	if err := db.PeerStateAction(req.Token, "unban", "", ""); err != nil {
		t.Fatal(err)
	}
	if p, _ := db.AccessPolicy(req.Token); p.Status != "pending" {
		t.Fatal("unban silently approved")
	}
}

func TestPoolAuthoritySharedDBAndRestartCannotLoseGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	db, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	first, err := db.BindServerPool(syntheticEnrollmentPool, true)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	second, err := other.BindServerPool(syntheticEnrollmentPool, true)
	if err != nil || second.AuthorityID != first.AuthorityID {
		t.Fatal("same local DB got independent authority", err)
	}
	independent := newTestDB(t)
	third, err := independent.BindServerPool(syntheticEnrollmentPool, true)
	if err != nil || third.AuthorityID == first.AuthorityID {
		t.Fatal("independent DB claimed shared authority", err)
	}
	for _, tc := range []struct {
		id    string
		login bool
	}{{"", false}, {strings.Repeat("b", 64), true}, {syntheticEnrollmentPool, false}} {
		if _, err := db.BindServerPool(tc.id, tc.login); err == nil {
			t.Fatal("restart silently changed authority/login policy")
		}
	}
	var authority string
	_ = db.QueryRow(`SELECT authority_id FROM server_pool_authority WHERE id=1`).Scan(&authority)
	if authority != first.AuthorityID {
		t.Fatal("failed rebind changed authority")
	}
}

func TestPoolConcurrentEnrollmentCannotExceedAccountLimit(t *testing.T) {
	db, _ := enrollmentFixture(t, true)
	account := createSyntheticEnrollmentAccount(t, db, 1)
	var wg sync.WaitGroup
	for _, suffix := range []string{"concurrent-a", "concurrent-b"} {
		req, _ := enrollmentIdentity(t, suffix)
		wg.Go(func() { _, _, _ = db.enrollPool(context.Background(), req, true, account) })
	}
	wg.Wait()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM peer_enrollments`).Scan(&n); err != nil || n != 1 {
		t.Fatal("account quota race", n, err)
	}
}

func TestPoolEnrollmentRejectsAmbiguousSchemaAndPlaintextPassword(t *testing.T) {
	_, h := enrollmentFixture(t, true)
	for _, raw := range []string{`null`, `{"pool_id":null}`, `{"token":"duplicate","token":"duplicate"}`, `{"Password":"not-exact-field"}`} {
		r := httptest.NewRequest(http.MethodPost, "https://entry.example/api/token/request", strings.NewReader(raw))
		w := httptest.NewRecorder()
		h.enrollPool(w, r)
		if w.Code != 400 {
			t.Fatal("bad schema passed", w.Code)
		}
	}
	req, key := enrollmentIdentity(t, "plain")
	req.Username, req.Password = "synthetic-user", syntheticEnrollmentPassword
	r, _ := enrollmentHTTP(req, key, "")
	r.TLS = nil
	r.RemoteAddr = "127.0.0.1:40000"
	w := httptest.NewRecorder()
	h.enrollPool(w, r)
	if w.Code != 403 {
		t.Fatal("plaintext local public request accepted credentials", w.Code)
	}
}

func TestPoolCapabilityReturnsBoundAuthorityAndNoSecrets(t *testing.T) {
	_, h := enrollmentFixture(t, true)
	r := httptest.NewRequest(http.MethodGet, serverpool.InfoPath, nil)
	w := httptest.NewRecorder()
	h.serverInfo(w, r)
	var info serverpool.Info
	if err := serverpool.DecodeStrict(w.Body.Bytes(), &info); err != nil || info.AuthorityID != h.poolAuthorityID || !info.ApprovalRequired || !info.LoginRequired {
		t.Fatal("invalid public capability", err)
	}
	if strings.Contains(w.Body.String(), "password") || strings.Contains(w.Body.String(), "token") {
		t.Fatal("capability disclosed credentials")
	}
}

func TestPoolHTTPProofJournalBoundsAndExpiry(t *testing.T) {
	db, _ := enrollmentFixture(t, false)
	if !db.claimPoolHTTPProof(t.Context(), "synthetic-nonce", time.Now().Unix()+120) || db.claimPoolHTTPProof(t.Context(), "synthetic-nonce", time.Now().Unix()+120) {
		t.Fatal("nonce freshness not durable")
	}
	if _, err := db.Exec(`UPDATE pool_http_proofs SET valid_until=?`, time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	if !db.claimPoolHTTPProof(t.Context(), "synthetic-after-expiry", time.Now().Unix()+120) {
		t.Fatal("expired proof entries did not free capacity")
	}
	if _, err := db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<8191) INSERT INTO pool_http_proofs(nonce,valid_until) SELECT 'fixture-'||x,? FROM n`, time.Now().Unix()+120); err != nil {
		t.Fatal(err)
	}
	if db.claimPoolHTTPProof(t.Context(), "cannot-evict-fresh-proof", time.Now().Unix()+120) {
		t.Fatal("full journal evicted valid proof or exceeded capacity")
	}
}
