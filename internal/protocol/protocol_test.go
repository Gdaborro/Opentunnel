package protocol

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestAddressRoundtrip(t *testing.T) {
	cases := []*Address{
		{Type: ATypIPv4, IP: []byte{192, 168, 1, 7}, Port: 443},
		{Type: ATypDomain, Domain: "example.com", Port: 8080},
		{Type: ATypIPv6, IP: net.ParseIP("2001:db8::1").To16(), Port: 993},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := c.Encode(&buf); err != nil {
			t.Fatalf("write %s: %v", c, err)
		}
		got, err := ReadAddress(&buf)
		if err != nil {
			t.Fatalf("read %s: %v", c, err)
		}
		if got.HostPort() != c.HostPort() || got.Type != c.Type {
			t.Fatalf("roundtrip mismatch: got %+v want %+v", got, c)
		}
	}
}

func TestParseAddress(t *testing.T) {
	a, err := ParseAddress("example.com", 443)
	if err != nil || a.Type != ATypDomain {
		t.Fatalf("domain parse: %v %+v", err, a)
	}
	a, err = ParseAddress("10.0.0.1", 80)
	if err != nil || a.Type != ATypIPv4 {
		t.Fatalf("ipv4 parse: %v %+v", err, a)
	}
	if _, err := ParseAddress("example.com", 0); err == nil {
		t.Fatal("port 0 must be rejected")
	}
}

// runWithTimeout fails the test instead of deadlocking on a misuse of pipes.
func runWithTimeout(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: operation did not complete within 5s")
	}
}

// tcpPipe returns two conns joined over loopback TCP. Unlike net.Pipe it is
// buffered, so writers never block on a not-yet-reading peer.
func tcpPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c net.Conn
		e error
	}
	serverCh := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		serverCh <- res{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-serverCh
	if s.e != nil {
		t.Fatal(s.e)
	}
	return client, s.c
}

func TestHandshakeRoundtrip(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	clientErr := make(chan error, 1)
	go func() {
		werr := WriteHandshake(clientConn, "secret-token")
		if werr != nil {
			clientErr <- werr
			return
		}
		clientErr <- ReadAuthResponse(clientConn)
	}()

	var status byte
	var err error
	runWithTimeout(t, func() {
		status, _, err = ReadAndVerifyHandshake(serverConn, serverConn, StaticVerifier("secret-token"))
	})
	if err != nil || status != StatusOK {
		t.Fatalf("handshake failed: status=%d err=%v", status, err)
	}
	select {
	case cerr := <-clientErr:
		if cerr != nil {
			t.Fatalf("client side: %v", cerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never finished handshake")
	}
}

func TestHandshakeRejectsWrongToken(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_ = WriteHandshake(clientConn, "wrong")
		_ = ReadAuthResponse(clientConn) // consume rejection status
	}()

	var status byte
	var err error
	runWithTimeout(t, func() {
		status, _, err = ReadAndVerifyHandshake(serverConn, serverConn, StaticVerifier("right"))
	})
	if status != StatusBadToken || !errors.Is(err, ErrBadToken) {
		t.Fatalf("expected bad-token rejection, got status=%d err=%v", status, err)
	}
}

func TestHandshakePolicyStatuses(t *testing.T) {
	cases := []struct {
		name   string
		verify func(string) byte
		status byte
	}{
		{"pending", func(string) byte { return StatusPending }, StatusPending},
		{"banned", func(string) byte { return StatusBanned }, StatusBanned},
		{"expired", func(string) byte { return StatusExpired }, StatusExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clientConn, serverConn := tcpPipe(t)
			defer clientConn.Close()
			defer serverConn.Close()

			clientErr := make(chan error, 1)
			go func() {
				_ = WriteHandshake(clientConn, "device-token")
				clientErr <- ReadAuthResponse(clientConn)
			}()

			var status byte
			var err error
			runWithTimeout(t, func() {
				status, _, err = ReadAndVerifyHandshake(serverConn, serverConn, c.verify)
			})
			if err != nil || status != c.status {
				t.Fatalf("server side: status=%d err=%v, want %d", status, err, c.status)
			}
			select {
			case cerr := <-clientErr:
				var ae *AuthError
				if !errors.As(cerr, &ae) || ae.Status != c.status {
					t.Fatalf("client side: %v, want AuthError status=%d", cerr, c.status)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("client never saw rejection")
			}
		})
	}
}

func TestHandshakeRejectsBadMagic(t *testing.T) {
	clientConn, serverConn := tcpPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = clientConn.Write([]byte{'X', 'X', 'X', 'X', 1, 0, 3, 'a', 'b', 'c'})
		buf := make([]byte, 16)
		for {
			if _, err := clientConn.Read(buf); err != nil {
				return
			}
		}
	}()

	var status byte
	var err error
	runWithTimeout(t, func() {
		status, _, err = ReadAndVerifyHandshake(serverConn, serverConn, StaticVerifier("tok"))
	})
	if status != StatusBadVersion || !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("expected version rejection, got status=%d err=%v", status, err)
	}
}

func TestTargetExchangeRoundtrip(t *testing.T) {
	addr, _ := ParseAddress("example.com", 443)

	c1, s1 := tcpPipe(t)
	defer c1.Close()
	defer s1.Close()
	errCh := make(chan error, 1)
	go func() {
		werr := WriteTarget(c1, addr)
		if werr != nil {
			errCh <- werr
			return
		}
		errCh <- ReadTargetResponse(c1)
	}()
	got, err := ReadTarget(s1)
	if err != nil || got.HostPort() != "example.com:443" {
		t.Fatalf("target read: %v %+v", err, got)
	}
	runWithTimeout(t, func() {
		if err := WriteTargetResponse(s1, StatusOK); err != nil {
			t.Errorf("write ok response: %v", err)
		}
	})
	select {
	case cerr := <-errCh:
		if cerr != nil {
			t.Fatalf("client must accept success reply, got: %v", cerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never consumed success reply")
	}

	// Failure statuses surface as errors on the client.
	c2, s2 := tcpPipe(t)
	defer c2.Close()
	defer s2.Close()
	go func() {
		_ = WriteTargetResponse(s2, StatusDialFailed)
		s2.Close()
	}()
	if err := ReadTargetResponse(c2); err == nil {
		t.Fatal("expected dial-failed status to be reported as an error")
	}
}
