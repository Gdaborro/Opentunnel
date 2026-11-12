package protocol

import (
	"strconv"
	"testing"
	"time"
)

func TestReplayCacheNeverEvictsUnexpiredSalts(t *testing.T) {
	rc := NewReplayCache(10*time.Minute, 100)
	// Fill to capacity with fresh salts.
	var recent []byte
	for i := 0; i < 100; i++ {
		recent = []byte("salt-" + strconv.Itoa(i))
		if !rc.CheckAndAdd(recent) {
			t.Fatalf("salt %d unexpectedly replayed", i)
		}
	}
	// Overflow with one more salt: cache must stay near capacity, not wipe.
	if rc.CheckAndAdd([]byte("overflow")) {
		t.Fatal("full cache admitted setup by discarding replay protection")
	}
	rc.mu.Lock()
	n := len(rc.m)
	_, recentSurvived := rc.m[string(recent)]
	rc.mu.Unlock()
	if n != 100 {
		t.Fatalf("cache size = %d, want 100", n)
	}
	if !recentSurvived {
		t.Fatal("unexpired salt was discarded")
	}
	// A replayed salt still in the cache is detected.
	if rc.CheckAndAdd([]byte("overflow")) {
		t.Fatal("replayed salt not detected")
	}
}
