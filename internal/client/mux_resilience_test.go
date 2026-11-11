package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMuxRoundRobinDoesNotCorruptPool(t *testing.T) {
	dials := 0
	p := newMuxPool(echoSessionFactory(&dials), 4, time.Second)
	defer p.Close()
	entries := make([]*muxEntry, 4)
	for i := range entries {
		entry, err := p.createSession(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		entries[i] = entry
		if err := p.add(entry); err != nil {
			t.Fatal(err)
		}
	}
	p.next = 3
	for i := 0; i < 12; i++ {
		if got := p.pick(); got != entries[(3+i)%4] {
			t.Fatal("round-robin traversal corrupted or duplicated the session list")
		}
		for j, entry := range p.sessions {
			if entry != entries[j] {
				t.Fatal("selection mutated the pool's backing slice")
			}
		}
	}
}

func TestMuxCapacityDoesNotCloseActiveStream(t *testing.T) {
	dials := 0
	p := newMuxPool(echoSessionFactory(&dials), 1, time.Second)
	p.softCap = 1
	defer p.Close()
	first, err := p.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := p.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = first.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := first.Write([]byte("still-alive")); err != nil {
		t.Fatalf("capacity replacement killed the original stream: %v", err)
	}
	buf := make([]byte, len("still-alive"))
	if _, err := io.ReadFull(first, buf); err != nil || string(buf) != "still-alive" {
		t.Fatal("original stream did not survive capacity spillover")
	}
	if _, err := p.Open(context.Background()); !errors.Is(err, ErrMuxCapacity) || dials != 2 {
		t.Fatal("total drain cap was not enforced before another handshake")
	}
}

func TestMuxSessionOutlivesCreatingRequest(t *testing.T) {
	dials := 0
	var sessionCtx context.Context
	p := newMuxPool(func(ctx context.Context) (net.Conn, error) {
		sessionCtx = ctx
		return echoSessionFactory(&dials)(ctx)
	}, 2, time.Second)
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := p.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	cancel()
	if sessionCtx.Err() != nil {
		t.Fatal("first request cancellation killed the pool-owned session")
	}
	_ = p.Close()
	if sessionCtx.Err() == nil {
		t.Fatal("pool shutdown did not cancel its session")
	}
}

func TestMuxWaiterTimeoutDoesNotCreateParallelHandshakes(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	p := newMuxPool(func(ctx context.Context) (net.Conn, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-gate:
			return nil, errors.New("synthetic failed setup")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, 2, time.Second)
	defer p.Close()
	done := make(chan struct{})
	go func() { _, _ = p.getOrDial(context.Background(), time.Second); close(done) }()
	<-started
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.getOrDial(context.Background(), 20*time.Millisecond) }()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("waiter timeout caused a handshake stampede: %d", calls.Load())
	}
	release.Do(func() { close(gate) })
	<-done
}
