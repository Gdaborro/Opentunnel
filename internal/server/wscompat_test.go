package server

import (
	"context"
	"net/http"
	"net/http/httptest"
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
