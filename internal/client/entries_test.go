package client

import (
	"context"
	"net"
	"testing"
	"time"

	"opentunnel/internal/transport"
)

func TestSetEntriesAndRotate(t *testing.T) {
	a := NewAdaptive("tok", transport.WSTLSOptions{ServerAddr: "a:443"}, "auto", 5*time.Second)
	a.SetEntries([]transport.WSTLSOptions{{ServerAddr: "a:443"}, {ServerAddr: "b:443"}})
	if a.EntryCount() != 2 {
		t.Fatalf("want 2 entries, got %d", a.EntryCount())
	}
	if !a.RotateEntry("test") {
		t.Fatal("rotate must succeed with 2 entries")
	}
	a.mu.Lock()
	base := a.base.ServerAddr
	idx := a.idx
	a.mu.Unlock()
	if base != "b:443" || idx != 0 {
		t.Fatalf("rotated base=%q idx=%d", base, idx)
	}
	// Single entry: nothing to rotate to.
	b := NewAdaptive("tok", transport.WSTLSOptions{ServerAddr: "a:443"}, "auto", 5*time.Second)
	b.SetEntries([]transport.WSTLSOptions{{ServerAddr: "a:443"}})
	if b.RotateEntry("test") {
		t.Fatal("single entry must not rotate")
	}
	b.SetEntries(nil) // ignored, must not panic or clear
	if b.EntryCount() != 1 {
		t.Fatal("empty SetEntries must be ignored")
	}
}

func TestIsDNSError(t *testing.T) {
	if !isDNSError(&net.DNSError{IsNotFound: true}) {
		t.Fatal("NXDOMAIN must classify as DNS failure")
	}
	if !isDNSError(errorString("dial tcp: lookup h: no such host")) {
		t.Fatal("no such host must classify as DNS failure")
	}
	if isDNSError(errorString("connection refused")) || isDNSError(nil) {
		t.Fatal("refusals must not classify as DNS failures")
	}
}

func TestIsShapedVerdict(t *testing.T) {
	if !isShaped(300*time.Millisecond, 40<<10) {
		t.Fatal("fast setup + 40KB/s must read as shaped")
	}
	if isShaped(300*time.Millisecond, 5<<20) {
		t.Fatal("fast setup + 5MB/s must not read as shaped")
	}
	if isShaped(8*time.Second, 40<<10) {
		t.Fatal("slow setup must not read as shaped (different problem)")
	}
	if isShaped(300*time.Millisecond, 0) {
		t.Fatal("zero throughput must not read as shaped")
	}
}

func TestThinModeFlag(t *testing.T) {
	SetThinMode(false)
	if ThinMode() {
		t.Fatal("thin must start off")
	}
	SetThinMode(true)
	if !ThinMode() {
		t.Fatal("thin must latch")
	}
	SetThinMode(false)
}

func TestProbeThroughputBadURL(t *testing.T) {
	a := NewAdaptive("tok", transport.WSTLSOptions{}, "auto", 5*time.Second)
	a.ProbeURL = "://bad-url"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := a.ProbeThroughput(ctx); err == nil {
		t.Fatal("bad probe URL must fail fast without network")
	}
}

func TestHealthShapedWiring(t *testing.T) {
	var shaped, healthy int
	h := &HealthReporter{
		ThroughputProbe: func(ctx context.Context) (time.Duration, float64, error) {
			return 300 * time.Millisecond, 40 << 10, nil
		},
		OnShaped:  func() { shaped++ },
		OnHealthy: func() { healthy++ },
	}
	for i := 0; i < 4; i++ {
		h.maybeThroughputProbe()
	}
	if shaped != 1 || healthy != 0 {
		t.Fatalf("4th report must fire shaped once, got s=%d h=%d", shaped, healthy)
	}
	h.ThroughputProbe = func(ctx context.Context) (time.Duration, float64, error) {
		return 300 * time.Millisecond, 5 << 20, nil
	}
	for i := 0; i < 4; i++ {
		h.maybeThroughputProbe()
	}
	if healthy != 1 {
		t.Fatalf("clean probe must fire healthy, got %d", healthy)
	}
}
