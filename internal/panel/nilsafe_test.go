package panel

import "testing"

// TestNilDBSafe pins the legacy no-panel contract: every relay-path method
// must tolerate a nil *DB (a typed-nil used to slip past the server's
// `PanelDB != nil` gate and panic the relay on first use — crashing the
// whole server process on a handshake).
func TestNilDBSafe(t *testing.T) {
	var db *DB
	if db.KillSwitch() {
		t.Fatal("nil KillSwitch must be false")
	}
	if db.IsBlocked("example.com") {
		t.Fatal("nil IsBlocked must be false")
	}
	if db.BlockWhy("example.com") != "" {
		t.Fatal("nil BlockWhy must be empty")
	}
	if status, _, _, _ := db.CheckToken("anything"); status != "pending" {
		t.Fatalf("nil CheckToken must be pending, got %q", status)
	}
	if maxBps, quota := db.PeerLimits("anything"); maxBps != 0 || quota != 0 {
		t.Fatal("nil PeerLimits must be unlimited")
	}
	if db.Setting("kill_switch") != "" {
		t.Fatal("nil Setting must be empty")
	}
	// Writes must be silent no-ops, not panics.
	db.RecordTraffic("anything", 1, 2)
	db.SetPeerIP("anything", "127.0.0.1")
}
