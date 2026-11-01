package server

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/protocol"
)

// verdict.go: per-stream identity verdicts (1.0.1 hardening).
//
// Bans, kicks, quotas and schedules used to be captured once at session
// setup: an already-connected peer kept opening streams indefinitely
// after the panel banned it (only the client's own status polling
// reacted, which a modified client simply ignores). relayTarget and
// serveUDPStream now re-check the LIVE verdict per stream through a 1s
// cache — cheap enough for the hot path, fast enough that enforcement
// lands within about a second.

type verdictEntry struct {
	status, reason, expires string
	at                      time.Time
}

var (
	verdictMu    sync.Mutex
	verdictCache = map[string]verdictEntry{}
)

const verdictTTL = time.Second

// currentVerdict returns the token's live panel verdict (1s cached).
// ok=false means no panel or the check failed — callers fall back to the
// session-start snapshot.
func (o Options) currentVerdict(token string) (status, reason, expires string, ok bool) {
	if o.PanelDB == nil || token == "" {
		return "", "", "", false
	}
	verdictMu.Lock()
	e, hit := verdictCache[token]
	verdictMu.Unlock()
	if hit && time.Since(e.at) < verdictTTL {
		return e.status, e.reason, e.expires, true
	}
	status, reason, expires, err := o.PanelDB.CheckToken(token)
	if err != nil {
		return "", "", "", false
	}
	verdictMu.Lock()
	if len(verdictCache) > 4096 { // bound the map under token floods
		for k, v := range verdictCache {
			if time.Since(v.at) > 10*time.Second {
				delete(verdictCache, k)
			}
		}
	}
	verdictCache[token] = verdictEntry{status: status, reason: reason, expires: expires, at: time.Now()}
	verdictMu.Unlock()
	return status, reason, expires, true
}

// writeBlocked emits the stream-level block response for a live verdict,
// reusing the exact wire forms the session-start path used so client
// block pages keep working ("banned:<reason>", "kicked:<reason>",
// "kicked-silent").
func writeBlocked(rw deadlineRW, ver byte, status, reason string) {
	_ = protocol.WriteTargetResponse(rw, ver, protocol.StatusBlocked)
	switch {
	case status == "banned":
		_ = protocol.WriteToken(rw, "banned:"+reason)
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
