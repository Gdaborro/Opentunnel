package proxy

import (
	"log"
	"sync"
	"time"
)

// logThrottle suppresses repeat log lines so a page that fires dozens of
// blocked ad domains (or a burst of dial failures) prints once instead of
// flooding the console. The panel records every event; the console only
// needs the first sighting.
type logThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

var throttle = &logThrottle{last: make(map[string]time.Time)}

// logThrottled logs the first occurrence of key immediately and suppresses
// repeats for window. Safe for concurrent use; nil logErr is a no-op.
func logThrottled(logErr *log.Logger, key string, window time.Duration, format string, args ...any) {
	if logErr == nil {
		return
	}
	now := time.Now()
	throttle.mu.Lock()
	if t, ok := throttle.last[key]; ok && now.Sub(t) < window {
		throttle.mu.Unlock()
		return
	}
	throttle.last[key] = now
	// Bound memory: drop entries older than the longest window we use.
	for k, t := range throttle.last {
		if now.Sub(t) > time.Hour {
			delete(throttle.last, k)
		}
	}
	throttle.mu.Unlock()
	logErr.Printf(format, args...)
}
