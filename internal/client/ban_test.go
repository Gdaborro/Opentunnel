//go:build windows

package client

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// regBanSnapshot preserves any pre-existing ban markers (e.g. this very
// machine may carry stale ones — the bug being fixed) so the test never
// alters live state.
func regBanSnapshot(t *testing.T) (reason, duration string, had bool, restore func()) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\OpenTunnel`, registry.QUERY_VALUE)
	if err != nil {
		return "", "", false, func() {}
	}
	reason, _, _ = k.GetStringValue("BanReason")
	duration, _, _ = k.GetStringValue("BanDuration")
	_, _, rerr := k.GetStringValue("BanReason")
	k.Close()
	return reason, duration, rerr == nil, func() {
		if !had {
			clearRegistryBan()
			return
		}
		writeRegistryBan(reason, duration)
	}
}

func TestBanRoundTrip(t *testing.T) {
	reason, duration, had, restore := regBanSnapshot(t)
	defer restore()

	ts := &TokenStore{Dir: t.TempDir()}
	if !had && ts.IsHardBanned() {
		t.Fatal("fresh temp store must not be banned")
	}
	ts.WriteHardBan("test reason", "permanent")
	if !ts.IsHardBanned() {
		t.Fatal("written ban must register")
	}
	data, err := os.ReadFile(filepath.Join(ts.Dir, "ban.json"))
	if err != nil || len(data) == 0 {
		t.Fatalf("ban.json missing: %v", err)
	}
	// ClearBan must drop both the file and registry markers.
	ts.ClearBan()
	if ts.IsHardBanned() {
		t.Fatal("ClearBan must lift the ban")
	}
	if _, err := os.Stat(filepath.Join(ts.Dir, "ban.json")); !os.IsNotExist(err) {
		t.Fatal("ban.json must be deleted")
	}

	// Live state must be exactly as before the test (restore is also
	// deferred, so early failures still reinstate the markers).
	restore()
	if had {
		k, err := registry.OpenKey(registry.CURRENT_USER, `Software\OpenTunnel`, registry.QUERY_VALUE)
		if err != nil {
			t.Fatalf("live marker lost: %v", err)
		}
		got, _, _ := k.GetStringValue("BanReason")
		k.Close()
		if got != reason {
			t.Fatalf("live marker altered: %q want %q", got, reason)
		}
		_ = duration
	}
}
