package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"opentunnel/internal/protocol"
)

// testPool builds a MuxPool whose factory dials a throwaway loopback smux
// server that accepts streams and discards them.
func testPool(t *testing.T, maxAge time.Duration) *MuxPool {
	t.Helper()
	p := newMuxPool(func(ctx context.Context) (net.Conn, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		go func() {
			defer ln.Close()
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := smux.Server(c, protocol.MuxConfig())
			if err != nil {
				c.Close()
				return
			}
			for {
				st, err := s.AcceptStream()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, st) }()
			}
		}()
		return net.Dial("tcp", ln.Addr().String())
	}, 4, 5*time.Second)
	p.maxAge = maxAge
	return p
}

func TestRotationRetiresOldSession(t *testing.T) {
	p := testPool(t, 80*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s1, err := p.Open(ctx)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	defer s1.Close()
	if n := p.NumSessions(); n != 1 {
		t.Fatalf("want 1 session, got %d", n)
	}
	// Outlive the rotation window, then open again: the old session must
	// drain (kept, not chosen) and the new stream must ride a fresh one.
	time.Sleep(200 * time.Millisecond)
	s2, err := p.Open(ctx)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer s2.Close()
	p.mu.Lock()
	if len(p.sessions) != 2 {
		p.mu.Unlock()
		t.Fatalf("want old draining + new session, got %d", len(p.sessions))
	}
	draining := 0
	for _, e := range p.sessions {
		if e.draining {
			draining++
		}
	}
	p.mu.Unlock()
	if draining != 1 {
		t.Fatalf("want exactly 1 draining session, got %d", draining)
	}
	// Once the old session empties, retire reaps it.
	_ = s1.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.retire()
		p.mu.Lock()
		n := len(p.sessions)
		p.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			if n != 1 {
				t.Fatalf("drained session not reaped, sessions=%d", n)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestKeepaliveJittered(t *testing.T) {
	for i := 0; i < 50; i++ {
		got := muxConfig().KeepAliveInterval
		if got < 20*time.Second || got > 30*time.Second {
			t.Fatalf("keepalive out of [20s, 30s]: %v", got)
		}
	}
}
