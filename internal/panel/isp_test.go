package panel

import (
	"path/filepath"
	"testing"
	"time"
)

func TestParseSchedule(t *testing.T) {
	cases := []struct {
		in      string
		allowed bool // whether a known time is allowed
	}{
		{"", true},
		{"0800-1800", true},
		{"bogus", true}, // malformed fails open
	}
	for _, c := range cases {
		days, wins := parseSchedule(c.in)
		if c.in == "" && (days != nil || wins != nil) {
			t.Fatalf("empty schedule must parse to nil: %+v %+v", days, wins)
		}
		if c.in == "0800-1800" && len(wins) != 1 {
			t.Fatalf("single window: %+v", wins)
		}
		if c.in == "bogus" && wins != nil {
			t.Fatal("bogus must fail open (nil windows)")
		}
	}
	// 10:00 inside 0800-1800
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC) // Wednesday
	if !scheduleAllows("0800-1800", now) {
		t.Fatal("10:00 should be inside 0800-1800")
	}
	if scheduleAllows("0800-1800", now.Add(9*time.Hour)) { // 19:00
		t.Fatal("19:00 should be outside 0800-1800")
	}
	// Weekday range: Wed inside Mon-Fri, Sat outside
	if !scheduleAllows("Mon-Fri 0000-2359", now) {
		t.Fatal("Wed should be inside Mon-Fri")
	}
	if scheduleAllows("Mon-Fri 0000-2359", now.AddDate(0, 0, 3)) { // Saturday
		t.Fatal("Sat should be outside Mon-Fri")
	}
	// Overnight window 2200-0600 allows 23:00 and 03:00, blocks 12:00
	late := time.Date(2026, 8, 26, 23, 0, 0, 0, time.UTC)
	if !scheduleAllows("2200-0600", late) {
		t.Fatal("23:00 should be inside overnight window")
	}
	if scheduleAllows("2200-0600", now) { // 10:00
		t.Fatal("10:00 should be outside overnight window")
	}
}

func TestNextScheduleStart(t *testing.T) {
	now := time.Date(2026, 8, 26, 19, 0, 0, 0, time.UTC) // Wed 19:00
	next := nextScheduleStart("0800-1800", now)
	if next.Hour() != 8 || next.Minute() != 0 {
		t.Fatalf("next start = %v, want 08:00", next)
	}
	if !next.After(now) {
		t.Fatal("next start must be in the future")
	}
}

func TestValidateSchedule(t *testing.T) {
	if !ValidateSchedule("") || !ValidateSchedule("Mon-Fri 0800-1800") || !ValidateSchedule("0800-1200,1300-1800") {
		t.Fatal("valid schedules rejected")
	}
	if ValidateSchedule("banana") || ValidateSchedule("2500-2600") {
		t.Fatal("invalid schedules accepted")
	}
}

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCategoryBlocking(t *testing.T) {
	db := newTestDB(t)
	if db.IsBlocked("facebook.com") {
		t.Fatal("categories start disabled")
	}
	if !db.SetCategoryEnabled("social", true) {
		t.Fatal("enable social")
	}
	invalidateBlockCache()
	if !db.IsBlocked("facebook.com") || !db.IsBlocked("sub.instagram.com") {
		t.Fatal("enabled category must suffix-match")
	}
	if db.IsBlocked("example.com") {
		t.Fatal("unrelated domain blocked")
	}
	if !db.SetCategoryEnabled("social", false) {
		t.Fatal("disable social")
	}
	invalidateBlockCache()
	if db.IsBlocked("facebook.com") {
		t.Fatal("disabled category must not block")
	}
	if db.SetCategoryEnabled("nonexistent", true) {
		t.Fatal("unknown category accepted")
	}
}

func TestKillSwitch(t *testing.T) {
	db := newTestDB(t)
	if db.KillSwitch() {
		t.Fatal("kill switch starts off")
	}
	db.SetKillSwitch(true)
	if !db.KillSwitch() {
		t.Fatal("kill switch should be on")
	}
	db.SetKillSwitch(false)
	if db.KillSwitch() {
		t.Fatal("kill switch should be off")
	}
}

func TestQuotaAndScheduleViaCheckToken(t *testing.T) {
	db := newTestDB(t)
	db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen,quota_bytes,bytes_up,bytes_down) VALUES('tok1','fp1','d','approved',datetime('now'),datetime('now'),1000,600,500)`)
	// 1100 used >= 1000 quota → kicked
	if status, reason, _, _ := db.CheckToken("tok1"); status != "kicked" || reason != "data quota exceeded" {
		t.Fatalf("quota: status=%s reason=%s", status, reason)
	}
	// Raise quota → approved again
	db.Exec(`UPDATE peers SET quota_bytes=0 WHERE token='tok1'`)
	if status, _, _, _ := db.CheckToken("tok1"); status != "approved" {
		t.Fatalf("unlimited quota: status=%s", status)
	}
	// Schedule that excludes now → kicked with a future retry time
	db.Exec(`UPDATE peers SET schedule=? WHERE token='tok1'`, "0000-0001")
	status, reason, expires, _ := db.CheckToken("tok1")
	if status != "kicked" || reason != "outside allowed hours (schedule)" || expires == "" {
		t.Fatalf("schedule: status=%s reason=%s expires=%s", status, reason, expires)
	}
}

func TestPeerLimitsAndIP(t *testing.T) {
	db := newTestDB(t)
	db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen) VALUES('tok2','fp2','d','approved',datetime('now'),datetime('now'))`)
	db.SetPeerLimits("tok2", "Mon-Fri 0800-1800", 125000, 5_000_000)
	bps, quota := db.PeerLimits("tok2")
	if bps != 125000 || quota != 5_000_000 {
		t.Fatalf("limits: bps=%d quota=%d", bps, quota)
	}
	db.SetPeerIP("tok2", "203.0.113.7")
	var ip string
	db.QueryRow(`SELECT last_ip FROM peers WHERE token='tok2'`).Scan(&ip)
	if ip != "203.0.113.7" {
		t.Fatalf("last_ip=%s", ip)
	}
}
