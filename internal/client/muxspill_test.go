package client

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSpilloverOpensFreshSession proves burst streams spill onto a new
// session instead of piling past the relay's per-session cap: with the soft
// cap at 2 and two streams held open, the next Open must mint session two.
func TestSpilloverOpensFreshSession(t *testing.T) {
	p := testPool(t, time.Hour)
	p.softCap = 2
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	held := []net.Conn{}
	for i := 0; i < 2; i++ {
		s, err := p.Open(ctx)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		defer s.Close()
		held = append(held, s)
	}
	// Give the server side a beat to register both streams.
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.mu.Lock()
		n := 0
		for _, e := range p.sessions {
			n += e.sess.NumStreams()
		}
		p.mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	s3, err := p.Open(ctx)
	if err != nil {
		t.Fatalf("spillover open: %v", err)
	}
	defer s3.Close()
	p.mu.Lock()
	n := len(p.sessions)
	p.mu.Unlock()
	if n != 2 {
		t.Fatalf("spillover must mint a second session, sessions=%d", n)
	}
	_ = held
}

// TestSoftCapDefaultBoundsRelayCap pins the relationship the design depends
// on: the client spills well below the relay's per-session drop cap.
func TestSoftCapDefaultBoundsRelayCap(t *testing.T) {
	p := newMuxPool(nil, 8, 5*time.Second)
	if p.softCap != softCapStreams {
		t.Fatalf("default softCap=%d", p.softCap)
	}
	if softCapStreams >= 256 {
		t.Fatalf("softCap %d must stay under the relay cap", softCapStreams)
	}
}
