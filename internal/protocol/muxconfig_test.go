package protocol

import (
	"testing"
	"time"
)

// TestMuxConfigKeepAliveJitter: per-session keepalive cadence must be
// randomized within bounds, with a receive-silence timeout that
// comfortably exceeds the peer's maximum cadence — a fleet pinging in
// lockstep is a flow-level correlation signature.
func TestMuxConfigKeepAliveJitter(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 64; i++ {
		cfg := MuxConfig()
		if cfg.KeepAliveInterval < 20*time.Second || cfg.KeepAliveInterval >= 35*time.Second {
			t.Fatalf("interval %v out of [20s, 35s)", cfg.KeepAliveInterval)
		}
		if cfg.KeepAliveTimeout < cfg.KeepAliveInterval+30*time.Second ||
			cfg.KeepAliveTimeout >= cfg.KeepAliveInterval+45*time.Second {
			t.Fatalf("timeout %v not within interval+[30s, 45s)", cfg.KeepAliveTimeout)
		}
		if cfg.KeepAliveTimeout <= 45*time.Second {
			t.Fatalf("timeout %v must exceed the peer's widest cadence (35s) with margin", cfg.KeepAliveTimeout)
		}
		if cfg.MaxFrameSize != 32768 {
			t.Fatalf("MaxFrameSize changed: %d", cfg.MaxFrameSize)
		}
		seen[cfg.KeepAliveInterval] = true
	}
	if len(seen) < 2 {
		t.Fatal("64 configs produced a single interval — jitter not applied")
	}
}
