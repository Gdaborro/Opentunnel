package client

import (
	"errors"
	"io"
	"net"
	"opentunnel/internal/transport"
	"testing"
	"time"
)

func TestDrainTimerNeverTerminatesActiveTransfer(t *testing.T) {
	dials := 0
	p := newMuxPool(echoSessionFactory(&dials), 1, time.Second)
	defer p.Close()
	stream, err := p.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	p.mu.Lock()
	entry := p.sessions[0]
	entry.draining = true
	entry.drainAt = time.Now().Add(-24 * time.Hour)
	p.mu.Unlock()
	p.retire()
	if entry.sess.IsClosed() {
		t.Fatal("rotation killed a long active transfer")
	}
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte("still-active")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("still-active"))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal("active transfer failed after drain", err)
	}
}

func TestAdaptiveRetainsShutdownOwnershipOfRetiredClients(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	a := NewAdaptive("", transport.WSTLSOptions{}, "fast", time.Second)
	cl := a.build(0)
	dials := 0
	cl.poolOnce.Do(func() { cl.pool = newMuxPool(echoSessionFactory(&dials), 1, time.Second) })
	stream, err := cl.getPool().Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	cl.pool.mu.Lock()
	session := cl.pool.sessions[0].sess
	cl.pool.mu.Unlock()
	a.EnableMux()
	a.mu.Lock()
	retiredCount := len(a.retiredClients)
	a.mu.Unlock()
	if retiredCount != 1 {
		t.Fatal("retired client lost its lifecycle owner")
	}
	if session.IsClosed() {
		t.Fatal("invalidating a tier killed active traffic")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	cl.pool.mu.Lock()
	closed, sessions := cl.pool.closed, len(cl.pool.sessions)
	cl.pool.mu.Unlock()
	if !closed || sessions != 0 {
		t.Fatal("adaptive shutdown leaked retired session")
	}
	if _, err := a.build(0).ProbeSession(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed adaptive created new clients", err)
	}
}
