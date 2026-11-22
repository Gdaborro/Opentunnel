package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sentinelTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedPeer(t *testing.T, db *DB, token, status string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen)
		VALUES(?, 'fp', 'dev', ?, datetime('now'), datetime('now'))`, token, status); err != nil {
		t.Fatalf("seed %s: %v", token, err)
	}
}

func seedIdentityPeer(t *testing.T, db *DB, token, status, fingerprint, key string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen,auth_epoch)
		VALUES(?,?,'dev',?,?,datetime('now'),datetime('now'),?)`, token, fingerprint, key, status, token+"-epoch"); err != nil {
		t.Fatalf("seed identity %s: %v", token, err)
	}
}

func identityStateSnapshot(t *testing.T, db *DB) string {
	t.Helper()
	var peers, fingerprintBans, keyBans, managedKeys string
	for query, dst := range map[string]*string{
		`SELECT COALESCE(group_concat(token||'|'||fingerprint||'|'||COALESCE(ssh_pubkey,'')||'|'||status||'|'||auth_epoch,';'),'') FROM (SELECT * FROM peers ORDER BY token)`: &peers,
		`SELECT COALESCE(group_concat(fingerprint||'|'||COALESCE(reason,''),';'),'') FROM (SELECT * FROM fingerprints_banned ORDER BY fingerprint)`:                           &fingerprintBans,
		`SELECT COALESCE(group_concat(pubkey||'|'||COALESCE(reason,''),';'),'') FROM (SELECT * FROM pubkeys_banned ORDER BY pubkey)`:                                          &keyBans,
		`SELECT COALESCE(group_concat(public_key||'|'||desired,';'),'') FROM (SELECT * FROM managed_ssh_keys ORDER BY public_key)`:                                            &managedKeys,
	} {
		if err := db.QueryRow(query).Scan(dst); err != nil {
			t.Fatalf("identity snapshot: %v", err)
		}
	}
	return peers + "\n" + fingerprintBans + "\n" + keyBans + "\n" + managedKeys
}

// TestAutoKick: kicks only approved, non-allowlisted devices; the kick
// carries a reason and an expiry.
func TestAutoKick(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "approved-token-123456", "approved")
	seedPeer(t, db, "pending-token-123456", "pending")
	seedPeer(t, db, "operator-token-123456", "approved")
	db.SetSetting("kill_switch_allow", "operator-token-123456")

	if !db.AutoKick("approved-token-123456", "auto: test", time.Now().Add(30*time.Minute)) {
		t.Fatal("approved peer must be kicked")
	}
	var status, reason, expires string
	if err := db.QueryRow(`SELECT status, COALESCE(kick_reason,''), COALESCE(kick_expires,'') FROM peers WHERE token='approved-token-123456'`).
		Scan(&status, &reason, &expires); err != nil || status != "kicked" || reason != "auto: test" || expires == "" {
		t.Fatalf("kick state = %q %q %q err=%v", status, reason, expires, err)
	}
	if db.AutoKick("pending-token-123456", "auto: test", time.Now()) {
		t.Fatal("pending peer must not be kicked")
	}
	if db.AutoKick("operator-token-123456", "auto: test", time.Now()) {
		t.Fatal("allowlisted operator device must never be auto-kicked")
	}
	// Repeat on an already-kicked peer is a no-op.
	if db.AutoKick("approved-token-123456", "auto: test2", time.Now()) {
		t.Fatal("already-kicked peer must not re-kick")
	}
}

// TestSetPeerIPHistory: one history row per IP change, none for repeats.
func TestSetPeerIPHistory(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "hist-token-1234567890", "approved")

	db.SetPeerIP("hist-token-1234567890", "203.0.113.5")
	db.SetPeerIP("hist-token-1234567890", "203.0.113.5")
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM peer_ips WHERE token='hist-token-1234567890'`).Scan(&n)
	if n != 1 {
		t.Fatalf("repeat IP must not add rows, got %d", n)
	}
	db.SetPeerIP("hist-token-1234567890", "198.51.100.9")
	db.QueryRow(`SELECT COUNT(*) FROM peer_ips WHERE token='hist-token-1234567890'`).Scan(&n)
	if n != 2 {
		t.Fatalf("IP change must add a row, got %d", n)
	}
	var last string
	db.QueryRow(`SELECT last_ip FROM peers WHERE token='hist-token-1234567890'`).Scan(&last)
	if last != "198.51.100.9" {
		t.Fatalf("last_ip = %q", last)
	}
}

func fakeCountry(ip string) string {
	switch ip {
	case "203.0.113.5":
		return "Germany"
	case "198.51.100.9":
		return "France"
	case "192.0.2.7":
		return "Germany"
	}
	return ""
}

// TestDetectTravel: two countries inside the window is a hit; one country,
// loopback rows and unknown-country rows are not.
func TestDetectTravel(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "travel-token-12345678", "approved")
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('travel-token-12345678','203.0.113.5',datetime('now','-20 minutes'))`)
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('travel-token-12345678','198.51.100.9',datetime('now','-2 minutes'))`)
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('travel-token-12345678','127.0.0.1',datetime('now','-1 minutes'))`)

	hits := db.DetectTravel(30*time.Minute, fakeCountry)
	if len(hits) != 1 {
		t.Fatalf("want 1 travel hit, got %+v", hits)
	}
	if h := hits[0]; h.Token != "travel-token-12345678" || h.A != "Germany (203.0.113.5)" || h.B != "France (198.51.100.9)" {
		t.Fatalf("unexpected hit: %+v", h)
	}

	// Same country only: no hit.
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('travel-token-12345678','192.0.2.7',datetime('now'))`)
	if hits := db.DetectTravel(30*time.Minute, fakeCountry); len(hits) != 1 {
		t.Fatalf("Germany→France→Germany is one hit pair, got %+v", hits)
	}

	// Rows outside the window do not count.
	db2 := sentinelTestDB(t)
	seedPeer(t, db2, "old-token-1234567890", "approved")
	db2.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('old-token-1234567890','203.0.113.5',datetime('now','-2 hours'))`)
	db2.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('old-token-1234567890','198.51.100.9',datetime('now','-1 hours'))`)
	if hits := db2.DetectTravel(30*time.Minute, fakeCountry); len(hits) != 0 {
		t.Fatalf("stale rows must not travel-hit, got %+v", hits)
	}
}

// TestDetectSpread: many distinct addresses for one device; loopback does
// not inflate the count.
func TestDetectSpread(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "spread-token-1234567", "approved")
	for i := 1; i <= 10; i++ {
		db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('spread-token-1234567',?,datetime('now','-1 hours'))`,
			fmt.Sprintf("203.0.113.%d", i))
	}
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('spread-token-1234567','127.0.0.1',datetime('now'))`)

	hits := db.DetectSpread(10, 24*time.Hour)
	if len(hits) != 1 || hits[0].N != 10 {
		t.Fatalf("want one hit with N=10, got %+v", hits)
	}
}

// TestDetectRegBurst: fresh registrations grouped by /24.
func TestDetectRegBurst(t *testing.T) {
	db := sentinelTestDB(t)
	for i := 0; i < 5; i++ {
		seedPeer(t, db, "reg-token-"+string(rune('a'+i))+"-1234567", "pending")
		db.Exec(`UPDATE peers SET last_ip=? WHERE token=?`, "203.0.113."+string(rune('1'+i)), "reg-token-"+string(rune('a'+i))+"-1234567")
	}
	seedPeer(t, db, "other-token-12345678", "pending")
	db.Exec(`UPDATE peers SET last_ip='198.51.100.5' WHERE token='other-token-12345678'`)

	hits := db.DetectRegBurst(5, time.Hour)
	if len(hits) != 1 || hits[0].Subnet != "203.0.113.0/24" || hits[0].N != 5 {
		t.Fatalf("want 203.0.113.0/24 x5, got %+v", hits)
	}
}

// TestSentinelTickTravelKicks: a travel hit alerts and (respond mode)
// auto-kicks; a second tick inside the throttle window does nothing.
func TestCountryChangeAlertsWithoutAutomaticKick(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "tick-token-123456789", "approved")
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('tick-token-123456789','203.0.113.5',datetime('now','-20 minutes'))`)
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('tick-token-123456789','198.51.100.9',datetime('now','-1 minutes'))`)

	db.SentinelTick(fakeCountry)

	var status string
	db.QueryRow(`SELECT status FROM peers WHERE token='tick-token-123456789'`).Scan(&status)
	if status != "approved" {
		t.Fatalf("country-only inference must not kick a device, status=%q", status)
	}
	var alerts int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind='sentinel' AND severity='warning'`).Scan(&alerts)
	if alerts != 1 {
		t.Fatalf("want 1 travel alert, got %d", alerts)
	}
	// Throttled: another tick must not duplicate anything.
	db.SentinelTick(fakeCountry)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind='sentinel' AND severity='warning'`).Scan(&alerts)
	if alerts != 1 {
		t.Fatalf("second tick must be throttled, got %d alerts", alerts)
	}
}

// TestSentinelTickOffIsSilent: mode off records nothing and kicks nobody.
func TestSentinelTickOffIsSilent(t *testing.T) {
	db := sentinelTestDB(t)
	db.SetSetting("sentinel_mode", "off")
	seedPeer(t, db, "off-token-1234567890", "approved")
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('off-token-1234567890','203.0.113.5',datetime('now','-20 minutes'))`)
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('off-token-1234567890','198.51.100.9',datetime('now','-1 minutes'))`)

	db.SentinelTick(fakeCountry)

	var status string
	db.QueryRow(`SELECT status FROM peers WHERE token='off-token-1234567890'`).Scan(&status)
	if status != "approved" {
		t.Fatalf("off mode must not kick, status=%q", status)
	}
	var alerts int
	db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alerts)
	if alerts != 0 {
		t.Fatalf("off mode must stay silent, got %d alerts", alerts)
	}
}

func TestSentinelDuplicateActiveIdentityIsReviewOnly(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		fingerprintA, fingerprintB string
		differentKey               bool
		want                       string
	}{
		{"same-key-different-fingerprint", "hwid-a", "hwid-b", false, "same canonical device public key with different hardware fingerprints"},
		{"same-fingerprint-different-key", "hwid-shared", "hwid-shared", true, "same hardware fingerprint with different device public keys"},
		{"both-same", "hwid-shared", "hwid-shared", false, "both the same canonical device public key and the same hardware fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := sentinelTestDB(t)
			keyA := testKeyLine(t)
			keyB := keyA
			if tc.differentKey {
				keyB = testKeyLine(t)
			}
			seedIdentityPeer(t, db, "duplicate-a-1234567890", "approved", tc.fingerprintA, keyA+" comment@example")
			seedIdentityPeer(t, db, "duplicate-b-1234567890", "approved", tc.fingerprintB, keyB)
			before := identityStateSnapshot(t, db)

			db.SentinelTick(nil)
			var severity, kind, message string
			if err := db.QueryRow(`SELECT severity,kind,message FROM alerts WHERE kind='security'`).Scan(&severity, &kind, &message); err != nil {
				t.Fatalf("duplicate identity alert: %v", err)
			}
			if severity != "warning" || kind != "security" || !strings.Contains(message, tc.want) ||
				!strings.Contains(message, "possible clone, reinstall, or spoof") || !strings.Contains(message, "review only") {
				t.Fatalf("unexpected duplicate finding: %s %s %s", severity, kind, message)
			}
			if after := identityStateSnapshot(t, db); after != before {
				t.Fatal("duplicate detection changed peer, key, status, epoch, managed-key, or identity-ban state")
			}
			var throttleKey string
			if err := db.QueryRow(`SELECT key FROM settings WHERE key LIKE 'sentinel_ts_duplicate-identity|%'`).Scan(&throttleKey); err != nil {
				t.Fatalf("digest throttle key: %v", err)
			}
			for _, raw := range []string{tc.fingerprintA, tc.fingerprintB, keyA, keyB} {
				if raw != "" && strings.Contains(throttleKey, raw) {
					t.Fatal("raw hardware fingerprint or public key leaked into throttle key")
				}
			}
			db.SentinelTick(nil)
			var alerts int
			if err := db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind='security'`).Scan(&alerts); err != nil || alerts != 1 {
				t.Fatalf("second tick was not throttled: alerts=%d err=%v", alerts, err)
			}
		})
	}
}

func TestSentinelDuplicateIdentityOffInactiveAndBounded(t *testing.T) {
	db := sentinelTestDB(t)
	key := testKeyLine(t)
	db.SetSetting("sentinel_mode", "off")
	seedIdentityPeer(t, db, "duplicate-off-a-123456", "approved", "hwid-off", key)
	seedIdentityPeer(t, db, "duplicate-off-b-123456", "approved", "hwid-off", key)
	before := identityStateSnapshot(t, db)
	db.SentinelTick(nil)
	var alerts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alerts); err != nil || alerts != 0 {
		t.Fatalf("off mode emitted duplicate findings: %d err=%v", alerts, err)
	}
	if after := identityStateSnapshot(t, db); after != before {
		t.Fatal("off-mode duplicate detection changed identity state")
	}

	db = sentinelTestDB(t)
	seedIdentityPeer(t, db, "duplicate-active-123456", "approved", "hwid-pending", key)
	seedIdentityPeer(t, db, "duplicate-pending-123456", "pending", "hwid-pending", key)
	before = identityStateSnapshot(t, db)
	db.SentinelTick(nil)
	if err := db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&alerts); err != nil || alerts != 1 {
		t.Fatalf("approved/pending duplicate did not emit one finding: %d err=%v", alerts, err)
	}
	if after := identityStateSnapshot(t, db); after != before {
		t.Fatal("approved/pending duplicate detection changed identity state")
	}

	for i := 0; i < 4; i++ {
		seedIdentityPeer(t, db, fmt.Sprintf("duplicate-bound-%d-123456", i), "approved", fmt.Sprintf("hwid-%d", i), key)
	}
	if hits := db.detectDuplicateIdentities(2); len(hits) != 2 {
		t.Fatalf("detector exceeded or missed its output bound: %+v", hits)
	}
}

func TestLegacySentinelRedirectsToIntegratedTab(t *testing.T) {
	db := sentinelTestDB(t)
	h := New(db, NewAuth(db), false)
	rr := httptest.NewRecorder()
	h.sentinelPage(rr, httptest.NewRequest("GET", "/admin/sentinel", nil))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/admin/#sentinel" {
		t.Fatalf("legacy redirect = %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

// TestAPISentinel: GET defaults to respond + lists findings; POST validates
// and persists the mode.
func TestAPISentinel(t *testing.T) {
	db := sentinelTestDB(t)
	h := New(db, NewAuth(db), false)

	rr := httptest.NewRecorder()
	h.apiSentinel(rr, httptest.NewRequest("GET", "/admin/api/sentinel", nil))
	if rr.Code != 200 {
		t.Fatalf("GET code %d", rr.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["mode"] != "respond" {
		t.Fatalf("default mode = %v, want respond", got["mode"])
	}

	rr = httptest.NewRecorder()
	h.apiSentinel(rr, httptest.NewRequest("POST", "/admin/api/sentinel", strings.NewReader(`{"mode":"nuke"}`)))
	if rr.Code != 400 {
		t.Fatalf("invalid mode must 400, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.apiSentinel(rr, httptest.NewRequest("POST", "/admin/api/sentinel", strings.NewReader(`{"mode":"alert"}`)))
	if rr.Code != 200 {
		t.Fatalf("POST code %d", rr.Code)
	}
	if v := db.Setting("sentinel_mode"); v != "alert" {
		t.Fatalf("persisted mode = %q, want alert", v)
	}

	// Sentinel and security findings surface in the same bounded recent feed.
	db.RecordAlert("warning", "sentinel", "test finding")
	db.RecordAlert("warning", "security", "test security finding")
	rr = httptest.NewRecorder()
	h.apiSentinel(rr, httptest.NewRequest("GET", "/admin/api/sentinel", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "test finding") || !strings.Contains(body, "test security finding") || !strings.Contains(body, `"mode":"alert"`) {
		t.Fatalf("GET payload missing finding/mode: %s", body)
	}
}

func TestLegacySentinelPageRedirectsToIntegratedTab(t *testing.T) {
	w := httptest.NewRecorder()
	new(Handler).sentinelPage(w, httptest.NewRequest(http.MethodGet, "/admin/sentinel", nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/admin/#sentinel" {
		t.Fatalf("legacy sentinel route = %d %q", w.Code, w.Header().Get("Location"))
	}
}

// TestSubnetKey: v4 groups by /24, v6 by /64.
func TestSubnetKey(t *testing.T) {
	if got := subnetKey("203.0.113.99"); got != "203.0.113.0/24" {
		t.Errorf("v4: %q", got)
	}
	if got := subnetKey("2001:db8:1:2:3:4:5:6"); got != "2001:db8:1:2::/64" {
		t.Errorf("v6: %q", got)
	}
	if got := subnetKey("garbage"); got != "" {
		t.Errorf("garbage: %q", got)
	}
}
