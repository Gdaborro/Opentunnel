package server

import (
	"net/http"
	"strings"

	"opentunnel/internal/protocol"
)

// writeBlocked emits the stream-level block response for a live verdict,
// reusing the exact wire forms the session-start path used so client
// block pages keep working ("banned:<reason>", "kicked:<reason>",
// "kicked-silent").
func writeBlocked(rw deadlineRW, ver byte, status, reason string) {
	_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusBlocked)
	switch {
	case status == "banned":
		_ = protocol.WriteToken(rw, "banned:"+reason)
	case status == "pending" || status == "expired":
		_ = protocol.WriteToken(rw, "blocked:"+status)
	case status == "unavailable":
		_ = protocol.WriteToken(rw, "blocked:admission unavailable")
	case status == "revoked":
		_ = protocol.WriteToken(rw, "blocked:session identity revoked; reconnect required")
	case status == "down":
		_ = protocol.WriteToken(rw, "blocked:down:"+reason)
	case strings.HasPrefix(reason, "silent:"):
		_ = protocol.WriteToken(rw, "kicked-silent")
	default:
		_ = protocol.WriteToken(rw, "kicked:"+reason)
	}
}

// SanitizeConnectionHeaders removes every header the CLIENT named in its
// Connection header, plus the Connection header itself (1.0.1). The
// stdlib reverse proxy strips hop-by-hop headers when it forwards, so a
// request carrying `Connection: X-Otu-Client-IP` used to delete the
// relay's trusted stamps AFTER they were set — collapsing the panel's
// per-IP rate limits and login lockout into one shared (loopback) bucket.
// The relay must sanitize before stamping.
func SanitizeConnectionHeaders(h http.Header) {
	for _, name := range strings.Split(h.Get("Connection"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			h.Del(name)
		}
	}
	h.Del("Connection")
}
