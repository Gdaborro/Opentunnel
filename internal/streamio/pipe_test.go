package streamio

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.AcceptTCP(); accepted <- c }()
	c, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, s
}

func TestPipeHalfClosedUploadGetsFullResponse(t *testing.T) {
	app, inbound := tcpPair(t)
	outbound, origin := tcpPair(t)
	done := make(chan struct{})
	go func() { defer close(done); _, _, _ = Pipe(context.Background(), inbound, outbound) }()
	go func() {
		defer origin.Close()
		body, _ := io.ReadAll(origin)
		_, _ = origin.Write(append([]byte("reply:"), body...))
	}()
	_ = app.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = app.Write([]byte("complete upload"))
	_ = app.CloseWrite()
	reply, err := io.ReadAll(app)
	if err != nil || string(reply) != "reply:complete upload" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers did not join")
	}
}

func TestPipeCancellationClosesAndJoinsBothWorkers(t *testing.T) {
	a, app := net.Pipe()
	b, origin := net.Pipe()
	defer app.Close()
	defer origin.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _, _, _ = Pipe(ctx, a, b) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled workers leaked")
	}
}
