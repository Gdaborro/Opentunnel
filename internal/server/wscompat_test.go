package server

import (
	"context"
	"io"
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
type killSwitchStub struct{ on bool }

func (k killSwitchStub) CheckToken(string) (string, string, string, error) {
	return "approved", "", "", nil
}
func (k killSwitchStub) RecordTraffic(string, int64, int64) {}
func (k killSwitchStub) IsBlocked(string) bool              { return false }
func (k killSwitchStub) BlockWhy(string) string             { return "" }
func (k killSwitchStub) KillSwitch() bool                   { return k.on }
func (k killSwitchStub) PeerLimits(string) (int64, int64)   { return 0, 0 }
func (k killSwitchStub) SetPeerIP(string, string)           {}
func (k killSwitchStub) RecordHealth(string, string, string, string, float64, float64, float64, int64, float64, float64, float64) {
}
func (k killSwitchStub) BanReason(string) string    { return "" }
func (k killSwitchStub) TouchPeer(string)           {}
func (k killSwitchStub) KnownPeer(string) bool      { return true }
func (k killSwitchStub) RecordVisit(string, string) {}

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

// TestKillSwitchServesDecoy: while suspended the endpoint answers with the
// site's own page and a 503 status — never a framework text blob.
func TestKillSwitchServesDecoy(t *testing.T) {
	h := Handler(Options{Token: "test-token-1234567890abcdef", PanelDB: killSwitchStub{on: true}})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+protocol.DefaultWSPath, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("content-type = %q, want the decoy page (text/html)", resp.Header.Get("Content-Type"))
	}
	if len(body) == 0 {
		t.Fatal("empty body: the kill switch must serve the decoy page")
	}
}
