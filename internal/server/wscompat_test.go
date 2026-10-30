package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"opentunnel/internal/protocol"
)

// TestWSPathsAcceptSubprotocollessDials proves both the boring default path
// and the legacy /ws path complete the WebSocket upgrade for clients that
// offer no subprotocol (the new boring handshake) and for clients sending
// an Origin header (older relays 403 those; ours must not). Auth rejection
// happens after upgrade, so dial success is the assertion (then we close).
func TestWSPathsAcceptSubprotocollessDials(t *testing.T) {
	h := Handler(Options{Token: "test-token-1234567890abcdef"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	dial := func(path string, hdr http.Header) {
		t.Helper()
		url := "ws://" + srv.Listener.Addr().String() + path
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		opts := &websocket.DialOptions{}
		if hdr != nil {
			opts.HTTPHeader = hdr
		}
		c, _, err := websocket.Dial(ctx, url, opts)
		if err != nil {
			t.Fatalf("dial %s: %v", path, err)
		}
		_ = c.Close(websocket.StatusNormalClosure, "")
	}

	for _, path := range []string{protocol.DefaultWSPath, protocol.LegacyWSPath} {
		dial(path, nil)
	}
	dial(protocol.DefaultWSPath, http.Header{"Origin": {"https://example.com"}})
}

// killSwitchStub implements server.Options.PanelDB for handler-level tests.
type killSwitchStub struct {
	on     bool
	reason string
	allow  map[string]bool

	// ssh-tier containment knobs (sshtier_test.go scenarios).
	peerMax                      int64
	sshMax, sshDaily, sshTrickle int64
}

func (k killSwitchStub) CheckToken(string) (string, string, string, error) {
	return "approved", "", "", nil
}
func (k killSwitchStub) RecordTraffic(string, int64, int64) {}
func (k killSwitchStub) IsBlocked(string) bool              { return false }
func (k killSwitchStub) BlockWhy(string) string             { return "" }
func (k killSwitchStub) KillSwitch() bool                   { return k.on }
func (k killSwitchStub) KillSwitchReason() string           { return k.reason }
func (k killSwitchStub) KillSwitchAllow(tok string) bool    { return k.allow[tok] }
func (k killSwitchStub) PeerLimits(string) (int64, int64)   { return k.peerMax, 0 }
func (k killSwitchStub) SSHTierLimits() (int64, int64, int64) {
	return k.sshMax, k.sshDaily, k.sshTrickle
}
func (k killSwitchStub) SetPeerIP(string, string) {}
func (k killSwitchStub) RecordHealth(string, string, string, string, float64, float64, float64, int64, float64, float64, float64) {
}
func (k killSwitchStub) BanReason(string) string            { return "" }
func (k killSwitchStub) TouchPeer(string)                   {}
func (k killSwitchStub) KnownPeer(string) bool              { return true }
func (k killSwitchStub) RecordVisit(string, string)         {}
func (k killSwitchStub) SSHPubKey(string) string            { return "" }
func (k killSwitchStub) RecordAlert(string, string, string) {}
func (k killSwitchStub) MarkV5(string)                      {}
func (k killSwitchStub) V5Seen(string) bool                 { return false }

// TestTunnelPathServesDecoyWithoutUpgrade: a plain GET on the tunnel path
// must answer with the site's own 404 page — the Go-native "404 page not
// found" text both fingerprinted the server and marked the endpoint for
// active probers.
func TestTunnelPathServesDecoyWithoutUpgrade(t *testing.T) {
	h := Handler(Options{Token: "test-token-1234567890abcdef"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{protocol.DefaultWSPath, protocol.LegacyWSPath} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("%s: content-type = %q, want the decoy page (text/html)", path, ct)
		}
		if strings.Contains(string(body), "page not found") {
			t.Errorf("%s: body carries the Go-native 404 fingerprint", path)
		}
	}
}

// TestKillSwitchBlocksStreamsWithReason: the kill switch is enforced
// per-stream now (upgrades are NOT refused — sessions must establish so
// clients can render the down page, and the allowlisted operator device
// must be able to connect). Non-allowlisted streams answer StatusBlocked
// with the "down:<admin reason>" payload; allowlisted tokens bypass it.
func TestKillSwitchBlocksStreamsWithReason(t *testing.T) {
	const tok = "blocked-device-token-123456"
	stub := killSwitchStub{on: true, reason: "shut down till further notice"}

	run := func(st killSwitchStub, token string) (byte, string) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go relayTarget(protocol.ATypIPv4, c2, Options{Token: "master", PanelDB: st}, token, "approved", "", protocol.ProtoVersionLegacy, "")
		// Target address bytes in a goroutine: net.Pipe is unbuffered and
		// the kill-switch path answers without reading the address, so a
		// synchronous write here deadlocks both ends.
		go func() { _, _ = c1.Write([]byte{127, 0, 0, 1, 0, 1}) }()
		_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp := make([]byte, 2)
		if _, err := io.ReadFull(c1, resp); err != nil {
			t.Fatalf("status read: %v", err)
		}
		reason := ""
		if resp[1] == protocol.StatusBlocked {
			if tokStr, err := protocol.ReadToken(c1); err == nil {
				reason = tokStr
			}
		}
		return resp[1], reason
	}

	st, reason := run(stub, tok)
	if st != protocol.StatusBlocked {
		t.Fatalf("blocked device: status=%d, want StatusBlocked", st)
	}
	if reason != "blocked:down:shut down till further notice" {
		t.Fatalf("reason payload = %q", reason)
	}

	// Allowlisted token bypasses the switch (dial to the unreachable test
	// target fails, which proves relayTarget proceeded past the gate).
	allowed := stub
	allowed.allow = map[string]bool{tok: true}
	if st, _ := run(allowed, tok); st == protocol.StatusBlocked {
		t.Fatal("allowlisted device must not be blocked by the kill switch")
	}
}
