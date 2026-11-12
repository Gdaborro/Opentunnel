package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

type udpTestDialer struct{ relay net.Conn }

func (d udpTestDialer) DialTunnel(context.Context, *protocol.Address) (net.Conn, error) {
	return nil, io.ErrClosedPipe
}
func (d udpTestDialer) OpenUDPRelay(context.Context) (net.Conn, error) { return d.relay, nil }

func TestUDPControlEOFTerminatesAssociation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		handleSocks(context.Background(), c, udpTestDialer{relay: a}, nil)
		close(done)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	// The complete UDP ASSOCIATE request includes its address, not just CMD.
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("reply=%v", reply)
	}
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("association survived control EOF")
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("relay was not closed")
	}
}

func TestMalformedUDPSourceCannotStealAssociation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(done)
			return
		}
		handleSocks(context.Background(), c, udpTestDialer{relay: a}, nil)
		close(done)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(c, make([]byte, 2))
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	bound := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(reply[8])<<8 | int(reply[9])}
	owner, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	foreign, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	var frame bytes.Buffer
	frame.Write([]byte{0, 0, 0})
	target, _ := protocol.ParseAddress("203.0.113.1", 53)
	_ = target.Encode(&frame)
	frame.WriteString("request")
	_, _ = owner.WriteToUDP(frame.Bytes(), bound)
	_ = b.SetDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := protocol.ReadUDPFrame(b); err != nil {
		t.Fatal(err)
	}
	_, _ = foreign.WriteToUDP([]byte{1, 0, 0, 1}, bound)
	_, _ = foreign.WriteToUDP(frame.Bytes(), bound)
	_ = b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := protocol.ReadUDPFrame(b); err == nil {
		t.Fatal("another UDP port was admitted to the established association")
	}
	_ = b.SetReadDeadline(time.Time{})
	go func() { _ = protocol.WriteUDPFrame(b, target, []byte("response")) }()
	_ = owner.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, _, err := owner.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := parseSocksUDPHeader(buf[:n])
	if err != nil || string(payload) != "response" {
		t.Fatalf("payload=%q err=%v", payload, err)
	}
	_ = foreign.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := foreign.ReadFromUDP(buf); err == nil {
		t.Fatal("foreign packet stole reply")
	}
	_ = c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("association did not stop")
	}
}

func FuzzSocksUDPHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 'x'})
	f.Add([]byte{0, 0, 1, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			return
		}
		_, _, _ = parseSocksUDPHeader(data)
	})
}
