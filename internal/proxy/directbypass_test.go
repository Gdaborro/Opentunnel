package proxy

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

type recordingDialer struct{ called bool }

func (r *recordingDialer) DialTunnel(ctx context.Context, t *protocol.Address) (net.Conn, error) {
	r.called = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

// TestDirectDialerShortCircuitsEntryHosts: targets matching a configured
// entry host dial straight out (loop protection without leaking operator
// domains into the visible WinINET bypass list); everything else flows to
// the tunnel dialer.
func TestDirectDialerShortCircuitsEntryHosts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	served := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		_ = c.Close()
		served <- line
	}()

	inner := &recordingDialer{}
	d := &DirectDialer{Inner: inner, Hosts: map[string]bool{"127.0.0.1": true}}
	addr, err := protocol.ParseAddress("127.0.0.1", ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	conn, err := d.DialTunnel(context.Background(), addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, _ = conn.Write([]byte("direct\n"))
	_ = conn.Close()
	if inner.called {
		t.Fatal("entry-host target must not enter the tunnel")
	}
	select {
	case line := <-served:
		if line != "direct\n" {
			t.Fatalf("listener saw %q, want the direct dial payload", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct dial never reached the listener")
	}

	// Ordinary targets flow to the tunnel dialer untouched.
	other, _ := protocol.ParseAddress("example.org", 443)
	if _, err := d.DialTunnel(context.Background(), other); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if !inner.called {
		t.Fatal("non-entry targets must go through the tunnel dialer")
	}
}
