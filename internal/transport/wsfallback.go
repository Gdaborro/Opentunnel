package transport

import (
	"net/http"

	"github.com/coder/websocket"

	"opentunnel/internal/protocol"
)

// wsDialFunc dials exactly one WebSocket path.
type wsDialFunc func(path string) (*websocket.Conn, *http.Response, error)

// dialWSWithLegacyFallback dials the primary path and returns on success. On
// a 404 it retries once on the legacy path: that status means an old relay
// that predates the boring-path migration (its mux serves the decoy 404 for
// unknown paths), so the legacy endpoint is the one place guaranteed to
// exist there. Any other outcome — and both-failed — returns the primary
// attempt's result, since that reflects the configured path.
func dialWSWithLegacyFallback(dial wsDialFunc, primary string) (*websocket.Conn, *http.Response, error) {
	conn, resp, err := dial(primary)
	if err == nil {
		return conn, resp, nil
	}
	if resp != nil && resp.StatusCode == http.StatusNotFound && primary != protocol.LegacyWSPath {
		if conn2, resp2, err2 := dial(protocol.LegacyWSPath); err2 == nil {
			return conn2, resp2, nil
		}
	}
	return conn, resp, err
}
