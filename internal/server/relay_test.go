package server

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

// TestRelaySurvivesSlowTransfer relays a slow upstream (~100 KB/s, ~15 s
// total) and requires every byte to arrive. It guards the large-download
// path: per-stream deadlines must never be left armed across the multi-minute
// data phase of a relayed connection.
func TestRelaySurvivesSlowTransfer(t *testing.T) {
	const total = 1536 * 1024 // 1.5 MB at ~100 KB/s ≈ 15 s (> any handshake guard)

	// Slow upstream: accepts one connection and paces bytes out.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upLn.Close()
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = byte(i)
		}
		tick := time.NewTicker(640 * time.Millisecond)
		defer tick.Stop()
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			<-tick.C
		}
	}()
	upAddr := upLn.Addr().(*net.TCPAddr)

	// Relay I/O pair: the test holds the client end, relayTarget the other.
	rwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	defer rwLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := rwLn.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	clientEnd, err := net.Dial("tcp", rwLn.Addr().String())
	if err != nil {
		t.Fatalf("relay dial: %v", err)
	}
	defer clientEnd.Close()
	var rw net.Conn
	select {
	case rw = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("relay accept timeout")
	}
	defer rw.Close()

	// Feed the target frame (ATYP already consumed by the caller convention).
	frame := append([]byte{}, upAddr.IP.To4()...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(upAddr.Port))
	frame = append(frame, port[:]...)
	if _, err := clientEnd.Write(frame); err != nil {
		t.Fatalf("target frame: %v", err)
	}

	opt := Options{AllowRestrictedTargets: true}
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayTarget(protocol.ATypIPv4, rw.(deadlineRW), opt, "", "approved", "")
	}()

	_ = clientEnd.SetDeadline(time.Now().Add(60 * time.Second))
	got, err := io.ReadFull(clientEnd, make([]byte, total))
	_ = clientEnd.Close()
	if err != nil {
		t.Fatalf("transfer died early after %d/%d bytes: %v", got, total, err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("relayTarget did not finish after full transfer")
	}
}
