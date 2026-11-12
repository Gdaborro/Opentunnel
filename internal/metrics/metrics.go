// Package metrics holds process-wide counters shared between the relay and
// the panel without coupling the two packages.
package metrics

import (
	"runtime"
	"sync/atomic"
	"time"
)

var activeSessions atomic.Int64

// SessionStarted marks a tunnel session beginning.
func SessionStarted() { activeSessions.Add(1) }

// SessionEnded marks a tunnel session ending.
func SessionEnded() { activeSessions.Add(-1) }

// ActiveSessions returns the current live tunnel session count.
func ActiveSessions() int64 { return activeSessions.Load() }

var started = time.Now()

type Snapshot struct {
	Version        string  `json:"version"`
	UptimeS        int64   `json:"process_uptime_s"`
	Goroutines     int     `json:"goroutines"`
	HeapMB         float64 `json:"heap_mb"`
	ActiveSessions int64   `json:"active_sessions"`
}

func Capture(version string) Snapshot {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return Snapshot{Version: version, UptimeS: int64(time.Since(started).Seconds()), Goroutines: runtime.NumGoroutine(), HeapMB: float64(ms.HeapAlloc) / (1024 * 1024), ActiveSessions: ActiveSessions()}
}
