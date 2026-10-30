package server

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// TestResolveClientIPTrustGating: CF-Connecting-IP is honored only when
// the TCP peer is a Cloudflare edge; a spoofed header from any other
// source (or any header when trust is off) must be ignored.
func TestResolveClientIPTrustGating(t *testing.T) {
	cfEdge := "104.16.1.1:443" // inside Cloudflare's 104.16.0.0/13
	other := "203.0.113.50:9999"

	req := httptest.NewRequest("GET", "/", nil)

	// Non-CF peer with spoofed header: peer wins.
	req.RemoteAddr = other
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	if got := ResolveClientIP(req, true); got != "203.0.113.50" {
		t.Fatalf("spoofed header from non-CF peer leaked: %q", got)
	}

	// CF peer with header: real client wins.
	req.RemoteAddr = cfEdge
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	if got := ResolveClientIP(req, true); got != "1.2.3.4" {
		t.Fatalf("CF-resolved IP = %q, want 1.2.3.4", got)
	}

	// CF peer, trust disabled: peer wins.
	if got := ResolveClientIP(req, false); got != "104.16.1.1" {
		t.Fatalf("trust off must ignore header, got %q", got)
	}

	// CF peer with garbage header: peer wins.
	req.Header.Set("CF-Connecting-IP", "not-an-ip")
	if got := ResolveClientIP(req, true); got != "104.16.1.1" {
		t.Fatalf("garbage header must fall back to peer, got %q", got)
	}
}

// TestGuardTokenSessionCap: loopback arrivals (the ssh tier's forward
// path) are bounded per identity even though per-IP caps exempt them.
func TestGuardTokenSessionCap(t *testing.T) {
	g := NewGuard(16, 1024, 0, 0)
	const tok = "tok-cap-test"
	var releases []func()
	for i := 0; i < maxSessionsPerToken; i++ {
		r := g.AcquireTokenSession(tok)
		if r == nil {
			t.Fatalf("session %d must be admitted", i)
		}
		releases = append(releases, r)
	}
	if r := g.AcquireTokenSession(tok); r != nil {
		t.Fatal("identity over cap must be denied")
	}
	releases[0]() // release one
	if r := g.AcquireTokenSession(tok); r == nil {
		t.Fatal("release must free a slot")
	} else {
		r()
	}
	if r := g.AcquireTokenSession("other-identity"); r == nil {
		t.Fatal("other identities are unaffected")
	}
}

// TestServeUDPStreamIdentityGate: banned and kicked devices get no UDP
// relay — identity enforcement used to stop at the TCP path.
func TestServeUDPStreamIdentityGate(t *testing.T) {
	for _, st := range []string{"banned", "kicked", "kicked-silent"} {
		rw1, rw2 := netPipePair(t)
		defer rw1.Close()
		defer rw2.Close()
		done := make(chan struct{})
		go func() {
			serveUDPStream(rw1, Options{}, "tok", st, "")
			close(done)
		}()
		select {
		case <-done:
			// stream closed without reading a frame: gate worked
		case <-time.After(2 * time.Second):
			t.Fatalf("peerStatus %q must close the stream immediately", st)
		}
	}
}

// netPipePair returns a connected, ready-made io.ReadWriteCloser pair.
func netPipePair(t *testing.T) (rw1, rw2 interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}) {
	t.Helper()
	c1, c2 := net.Pipe()
	return c1, c2
}
