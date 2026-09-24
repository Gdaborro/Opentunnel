package transport

import (
	"errors"
	"net/http"
	"testing"

	"github.com/coder/websocket"

	"opentunnel/internal/protocol"
)

func notFoundResp() *http.Response {
	return &http.Response{StatusCode: http.StatusNotFound}
}

// TestLegacyFallbackRetriesOldRelay proves the migration safety net: a fresh
// client dialing the boring path against a pre-migration relay (decoy 404)
// retries once on /ws and succeeds. This is the exact outage class where a
// new client meets an old server.
func TestLegacyFallbackRetriesOldRelay(t *testing.T) {
	calls := []string{}
	dial := func(path string) (*websocket.Conn, *http.Response, error) {
		calls = append(calls, path)
		if path == protocol.DefaultWSPath {
			return nil, notFoundResp(), errors.New("expected handshake response status code 101 but got 404")
		}
		if path == protocol.LegacyWSPath {
			return &websocket.Conn{}, &http.Response{StatusCode: 101}, nil
		}
		t.Fatalf("unexpected path %q", path)
		return nil, nil, nil
	}
	conn, _, err := dialWSWithLegacyFallback(dial, protocol.DefaultWSPath)
	if err != nil {
		t.Fatalf("fallback must succeed: %v", err)
	}
	if conn == nil {
		t.Fatal("want a connection")
	}
	if len(calls) != 2 || calls[0] != protocol.DefaultWSPath || calls[1] != protocol.LegacyWSPath {
		t.Fatalf("want [boring legacy] attempts, got %v", calls)
	}
}

func TestLegacyFallbackSkipsNon404(t *testing.T) {
	calls := 0
	dial := func(path string) (*websocket.Conn, *http.Response, error) {
		calls++
		return nil, nil, errors.New("connection refused")
	}
	_, _, err := dialWSWithLegacyFallback(dial, protocol.DefaultWSPath)
	if err == nil {
		t.Fatal("must propagate non-404 failures")
	}
	if calls != 1 {
		t.Fatalf("no retry on non-404, got %d calls", calls)
	}
}

func TestLegacyFallbackPrimaryWins(t *testing.T) {
	calls := 0
	dial := func(path string) (*websocket.Conn, *http.Response, error) {
		calls++
		return &websocket.Conn{}, &http.Response{StatusCode: 101}, nil
	}
	if _, _, err := dialWSWithLegacyFallback(dial, protocol.DefaultWSPath); err != nil {
		t.Fatalf("primary success must stand: %v", err)
	}
	if calls != 1 {
		t.Fatalf("no retry when primary succeeds, got %d calls", calls)
	}
}
