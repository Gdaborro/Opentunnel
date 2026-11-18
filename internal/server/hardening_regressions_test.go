package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"opentunnel/internal/access"
	"opentunnel/internal/protocol"
)

func TestMalformedAnonymousProbeHasNoProtocolVerdict(t *testing.T) {
	srv := httptest.NewServer(Handler(Options{Logger: log.New(io.Discard, "", 0), Guard: NewGuard(100, 100, time.Second, time.Minute)}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+srv.URL[4:]+protocol.DefaultWSPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	c := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	if _, err := c.Write([]byte("NOT-A-TUNNEL-PROBE")); err != nil {
		t.Fatal(err)
	}
	var verdict [2]byte
	if _, err := io.ReadFull(c, verdict[:]); err == nil && bytes.Equal(verdict[:], []byte{protocol.ProtoVersion, protocol.StatusBadVersion}) {
		t.Fatal("anonymous probe received protocol oracle")
	}
}

func TestAbuseStateIsBoundedForRecentSourcesAndSingleSource(t *testing.T) {
	s := NewSentinel(nil, nil)
	for i := range 10000 {
		s.hit("probe", fmt.Sprintf("198.51.%d.%d", i/256, i%256), time.Minute)
		s.throttle(fmt.Sprintf("probe-%d", i), time.Hour)
	}
	if len(s.buckets) > maxSentinelBuckets || len(s.seen) > maxSentinelThrottles {
		t.Fatal("expiry-only abuse state exceeds cardinality cap")
	}
	single := NewSentinel(nil, nil)
	for range 20000 {
		single.hit("denied", "192.0.2.88", time.Minute)
	}
	if len(single.buckets["denied\x00192.0.2.88"]) > maxSentinelEvents {
		t.Fatal("single subject has unbounded timestamps")
	}
	g := NewGuard(16, 1024, time.Second, time.Minute)
	for i := range 10000 {
		ip := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		g.Punish(ip)
		g.BanIP(ip, time.Minute)
	}
	if len(g.fails) > maxGuardSources || len(g.bans) > maxGuardSources {
		t.Fatal("guard state exceeded source cap")
	}
	subjects, throttles, _ := s.CapacityCounters()
	_, _, saturated := single.CapacityCounters()
	if subjects == 0 || throttles == 0 || saturated == 0 || g.DroppedSources() == 0 {
		t.Fatal("bounded saturation became invisible")
	}
}

func TestLimiterSourceCardinalityFailsClosedAtCapacity(t *testing.T) {
	opt := Options{state: newRelayState()}
	for i := range 10000 {
		_ = opt.limit(fmt.Sprintf("synthetic-device-%d", i), "device", 1024)
	}
	if len(opt.state.limits) > 8192 {
		t.Fatal("rate limiter memory grew past hard cap")
	}
	if err := opt.pace(t.Context(), "another-new-source", "", access.Snapshot{MaxBps: 1024}, 1); err == nil {
		t.Fatal("limiter capacity disabled configured rate enforcement")
	}
}

func TestGuardReleaseCannotFreeAnotherConnection(t *testing.T) {
	g := NewGuard(4, 2, time.Second, time.Minute)
	a, b := g.Acquire("192.0.2.1"), g.Acquire("192.0.2.2")
	if a == nil || b == nil {
		t.Fatal("fixture cap unexpectedly full")
	}
	a()
	a()
	c := g.Acquire("192.0.2.3")
	if c == nil {
		t.Fatal("released slot unavailable")
	}
	defer c()
	defer b()
	if extra := g.Acquire("192.0.2.4"); extra != nil {
		extra()
		t.Fatal("duplicate release freed another active slot")
	}
}
