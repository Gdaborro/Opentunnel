package client

import (
	"testing"
	"time"

	"opentunnel/internal/transport"
)

func TestJitteredBounds(t *testing.T) {
	setHostileMode(false)
	for i := 0; i < 200; i++ {
		got := jittered(15 * time.Second)
		if got < 15*time.Second || got > 15*time.Second+7500*time.Millisecond {
			t.Fatalf("jitter out of [15s, 22.5s]: %v", got)
		}
	}
	if jittered(0) != 0 {
		t.Fatal("jittered(0) must be 0")
	}
	// Hostile quadruples the base before jitter.
	setHostileMode(true)
	defer setHostileMode(false)
	got := jittered(15 * time.Second)
	if got < 60*time.Second || got > 90*time.Second {
		t.Fatalf("hostile jitter out of [60s, 90s]: %v", got)
	}
}

func TestAdaptiveReset(t *testing.T) {
	a := NewAdaptive("tok", transport.WSTLSOptions{}, "auto", 5*time.Second)
	a.idx = 2
	a.failStreak = 3
	a.lastProbe = time.Now()
	a.Reset()
	if a.idx != 0 || a.failStreak != 0 || !a.lastProbe.IsZero() {
		t.Fatalf("Reset must restore fast/zero state, got idx=%d", a.idx)
	}
	// Fixed profiles ignore Reset (explicit user choice).
	f := NewAdaptive("tok", transport.WSTLSOptions{}, "stealth", 5*time.Second)
	f.idx = 2
	f.Reset()
	if f.idx != 2 {
		t.Fatal("Reset must not touch fixed profiles")
	}
}

func TestHostileTierGate(t *testing.T) {
	setHostileMode(false)
	a := NewAdaptive("tok", transport.WSTLSOptions{}, "auto", 5*time.Second)
	a.EnableSSHFallback(func() transport.Transport { return nil })
	if got := a.tierCount(); got != 4 {
		t.Fatalf("want 4 tiers with SSH fallback, got %d", got)
	}
	a.SetHostile(true)
	defer setHostileMode(false)
	if !HostileMode() {
		t.Fatal("global hostile flag must latch")
	}
	if got := a.tierCount(); got != 3 {
		t.Fatalf("hostile must hide the SSH tier, got %d tiers", got)
	}
	if a.Current() != ProfileStealth {
		t.Fatalf("hostile must lock stealth shaping, current=%q", a.Current())
	}
	a.AllowHostileSSH = true
	if got := a.tierCount(); got != 4 {
		t.Fatalf("explicit opt-in must restore SSH tier, got %d", got)
	}
	a.SetHostile(false)
	if HostileMode() {
		t.Fatal("hostile flag must clear")
	}
}

func TestPinFailureClassifier(t *testing.T) {
	for _, msg := range []string{
		"transport: server certificate fingerprint mismatch",
		"x509: certificate is not trusted",
		"tls: failed to verify certificate: x509: certificate signed by unknown authority",
	} {
		if !isPinFailure(errorString(msg)) {
			t.Fatalf("must classify as pin failure: %q", msg)
		}
	}
	if isPinFailure(errorString("connection refused")) || isPinFailure(nil) {
		t.Fatal("must not classify network errors as pin failures")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
