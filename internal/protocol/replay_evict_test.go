package protocol

import (
	"strconv"
	"testing"
	"time"
)

func TestReplayCacheEvictsInsteadOfWiping(t *testing.T) {
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
	if !rc.CheckAndAdd([]byte("overflow")) {
		t.Fatal("overflow salt unexpectedly replayed")
	}
	rc.mu.Lock()
	n := len(rc.m)
	_, recentSurvived := rc.m[string(recent)]
	rc.mu.Unlock()
	if n > 100 || n < 80 {
		t.Fatalf("cache size after eviction = %d, want ~90-100", n)
	}
	if !recentSurvived {
		t.Log("note: random eviction dropped the newest salt (probabilistic, acceptable)")
	}
	// A replayed salt still in the cache is detected.
	if rc.CheckAndAdd([]byte("overflow")) {
		t.Fatal("replayed salt not detected")
	}
}
