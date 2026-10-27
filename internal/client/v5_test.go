package client

import (
	"context"
	"net"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

// TestEverApprovedMarker: the marker is fingerprint-keyed and durable —
// a forced token rotation (new token, same fingerprint) cannot reset it,
// while a different fingerprint reads false.
func TestEverApprovedMarker(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	ts, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	if ts.EverApproved("fp-a") {
		t.Fatal("fresh store must not report ever-approved")
	}
	ts.MarkApproved("fp-a")
	if !ts.EverApproved("fp-a") {
		t.Fatal("marker must persist for the approved fingerprint")
	}
	if ts.EverApproved("fp-b") {
		t.Fatal("marker must not apply to a different fingerprint")
	}
	// Re-marking with a new fingerprint (identity change) moves the marker.
	ts.MarkApproved("fp-b")
	if ts.EverApproved("fp-a") || !ts.EverApproved("fp-b") {
		t.Fatal("re-marking must rekey the marker")
	}
}

// pipeTransport returns one end of a net.Pipe per Dial, handing the other
// end to fn so a test can script the server side.
type pipeTransport struct {
	serverFn func(net.Conn)
}

func (p *pipeTransport) Name() string { return "pipe" }
func (p *pipeTransport) Dial(ctx context.Context) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go p.serverFn(c2)
	return c1, nil
}

// TestV5FallsBackToLegacyServer: a pre-v5 relay rejects the v5 handshake
// with {version 4, BadVersion}; the client must retry the same connection
// with the legacy unsigned handshake and succeed.
func TestV5FallsBackToLegacyServer(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	tr := &pipeTransport{serverFn: func(c net.Conn) {
		defer c.Close()
		// Read the v5 hello (magic4 + ver1 + len2 + tok43... read loosely):
		buf := make([]byte, 2048)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err != nil || n < 7 {
			t.Errorf("server: short read %d: %v", n, err)
			return
		}
		if buf[4] != protocol.ProtoVersion {
			t.Errorf("server: expected v5 hello, got version %d", buf[4])
			return
		}
		// Legacy verdict: echo version 4 + BadVersion.
		_, _ = c.Write([]byte{protocol.ProtoVersionLegacy, protocol.StatusBadVersion})
		// Expect the v4 retry, then answer OK.
		n, err = c.Read(buf)
		if err != nil || n < 7 {
			t.Errorf("server: retry read %d: %v", n, err)
			return
		}
		if buf[4] != protocol.ProtoVersionLegacy {
			t.Errorf("server: expected v4 retry, got version %d", buf[4])
			return
		}
		_, _ = c.Write([]byte{protocol.ProtoVersionLegacy, protocol.StatusOK})
		// Hold the conn briefly so the client's read lands before close.
		time.Sleep(200 * time.Millisecond)
	}}

	cl := NewWithOptions(tr, Options{Token: "device-token-1234567890", DialTimeout: 5 * time.Second})
	raw, tok, salt, err := cl.dialAuthenticated(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial with legacy fallback: %v", err)
	}
	defer raw.Close()
	if tok != "device-token-1234567890" {
		t.Fatalf("token = %q", tok)
	}
	if salt != nil {
		t.Fatal("legacy fallback must leave the salt for the caller to write")
	}
}

// TestV5SentWhenKeyExists: with a device key on disk the client must send
// a v5 hello (version byte 5) and keep the salt it carried.
func TestV5SentWhenKeyExists(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	ts, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.EnsureSSHKey(); err != nil {
		t.Fatal(err)
	}
	sawV5 := make(chan struct{}, 1)
	tr := &pipeTransport{serverFn: func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 2048)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(buf)
		if err != nil || n < 7 {
			return
		}
		if buf[4] == protocol.ProtoVersion {
			sawV5 <- struct{}{}
		}
		_, _ = c.Write([]byte{protocol.ProtoVersion, protocol.StatusOK})
		time.Sleep(200 * time.Millisecond)
	}}

	cl := NewWithOptions(tr, Options{Token: "device-token-1234567890", DialTimeout: 5 * time.Second})
	raw, _, salt, err := cl.dialAuthenticated(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	select {
	case <-sawV5:
	case <-time.After(2 * time.Second):
		t.Fatal("client never sent a v5 handshake despite having a device key")
	}
	if salt == nil || len(salt) != protocol.SaltSize {
		t.Fatalf("v5 must return the in-handshake salt, got %v", salt)
	}
}
