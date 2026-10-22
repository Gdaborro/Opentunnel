package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/transport"
)

var (
	testPinA = strings.Repeat("aa", 32)
	testPinB = strings.Repeat("bb", 32)
	testPinC = strings.Repeat("cc", 32)
)

// TestExtraPinRoundTrip: learned pins persist, dedupe, and reload.
func TestExtraPinRoundTrip(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	SaveExtraPin(testPinA)
	SaveExtraPin(strings.ToUpper(testPinA)) // same pin, different case
	SaveExtraPin(testPinB)
	pins := LoadExtraPins()
	if len(pins) != 2 {
		t.Fatalf("pins = %v; want deduped [A B]", pins)
	}
	// The journal lives in the product data dir, not the exe dir.
	ts, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ts.Dir, "pins.json")); err != nil {
		t.Fatalf("pins.json missing: %v", err)
	}
}

// TestAdaptiveAddPin: rotation pins join the base config and every entry
// that lacks them (entries share the server's cert, so a learned pin
// heals the whole pool); pins already known everywhere are no-ops; the
// tier cache is invalidated so new dials use the extended set.
func TestAdaptiveAddPin(t *testing.T) {
	a := NewAdaptive("tok", transport.WSTLSOptions{Fingerprint: testPinA}, "auto", time.Second)
	a.SetEntries([]transport.WSTLSOptions{
		{Fingerprint: testPinA},
		{Fingerprint: testPinC},
	})
	if !a.AddPin(testPinB) {
		t.Fatal("new pin must be added")
	}
	if a.AddPin(testPinB) {
		t.Fatal("duplicate pin must be a no-op")
	}
	// The primary of entry0 is unknown to entry1: learning it there is
	// still a change (and a legitimate one — entries share the cert).
	if !a.AddPin(testPinA) {
		t.Fatal("pin known only to some entries must still heal the rest")
	}
	if a.AddPin(testPinA) {
		t.Fatal("fully-known pin must be a no-op")
	}
	if a.AddPin("  ") {
		t.Fatal("blank pin must be ignored")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) != 2 {
		t.Fatalf("entries = %d", len(a.entries))
	}
	if len(a.entries[0].Fingerprints) != 1 || a.entries[0].Fingerprints[0] != testPinB {
		t.Fatalf("entry0 rotation set = %v", a.entries[0].Fingerprints)
	}
	if len(a.entries[1].Fingerprints) != 2 {
		t.Fatalf("entry1 rotation set = %v (want learned B and healed A)", a.entries[1].Fingerprints)
	}
	if a.clients != nil {
		t.Fatal("tier cache must be invalidated after AddPin")
	}
}
