package panel

import (
	"fmt"
	"path/filepath"
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
func TestSentinelTickTravelKicks(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "tick-token-123456789", "approved")
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('tick-token-123456789','203.0.113.5',datetime('now','-20 minutes'))`)
	db.Exec(`INSERT INTO peer_ips(token,ip,at) VALUES('tick-token-123456789','198.51.100.9',datetime('now','-1 minutes'))`)

	db.SentinelTick(fakeCountry)

	var status string
	db.QueryRow(`SELECT status FROM peers WHERE token='tick-token-123456789'`).Scan(&status)
	if status != "kicked" {
		t.Fatalf("respond mode must auto-kick the traveling device, status=%q", status)
	}
	var alerts int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind='sentinel' AND severity='critical'`).Scan(&alerts)
	if alerts != 1 {
		t.Fatalf("want 1 travel alert, got %d", alerts)
	}
	// Throttled: another tick must not duplicate anything.
	db.SentinelTick(fakeCountry)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind='sentinel' AND severity='critical'`).Scan(&alerts)
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
