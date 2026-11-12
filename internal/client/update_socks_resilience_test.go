package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestUpdateSOCKSStalledHandshakeClosesOnCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	closed := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer c.Close()
		// Read the greeting but never acknowledge it. The setup context must
		// close this socket rather than leaving a detached Dial goroutine.
		_, err = io.Copy(io.Discard, c)
		closed <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if c, err := socksDialContext(ctx, ln.Addr().String(), "tcp", "127.0.0.1:1"); err == nil {
		_ = c.Close()
		t.Fatal("stalled SOCKS handshake succeeded")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled update left SOCKS authentication socket alive")
	}
}
