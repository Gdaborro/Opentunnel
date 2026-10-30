package panel

import "testing"

// TestSSHTierLimits: the ssh-tier containment settings parse into the
// bytes/sec cap, per-device daily budget (MB → bytes) and trickle rate
// (kbps → bytes/sec) the relay consumes, with a 200 kbps default trickle
// whenever a budget is configured. Invalid values fall back to off.
func TestSSHTierLimits(t *testing.T) {
	db := newTestDB(t)

	if maxBps, daily, trickle := db.SSHTierLimits(); maxBps != 0 || daily != 0 || trickle != 0 {
		t.Fatalf("unset policy must be off, got %d/%d/%d", maxBps, daily, trickle)
	}

	db.SetSetting("ssh_tier_max_bps", "250000")
	db.SetSetting("ssh_tier_daily_mb", "10")
	maxBps, daily, trickle := db.SSHTierLimits()
	if maxBps != 250000 || daily != 10<<20 || trickle != defaultSSHTrickleBps {
		t.Fatalf("policy = %d/%d/%d, want 250000/%d/%d",
			maxBps, daily, trickle, 10<<20, defaultSSHTrickleBps)
	}

	db.SetSetting("ssh_tier_trickle_kbps", "500")
	if _, _, trickle := db.SSHTierLimits(); trickle != 500*1000/8 {
		t.Fatalf("explicit trickle = %d, want %d", trickle, 500*1000/8)
	}

	// Invalid or negative values fall back to off/defaults.
	db.SetSetting("ssh_tier_max_bps", "bogus")
	db.SetSetting("ssh_tier_daily_mb", "-5")
	db.SetSetting("ssh_tier_trickle_kbps", "")
	if maxBps, daily, trickle := db.SSHTierLimits(); maxBps != 0 || daily != 0 || trickle != 0 {
		t.Fatalf("invalid policy must reset to off, got %d/%d/%d", maxBps, daily, trickle)
	}
}
