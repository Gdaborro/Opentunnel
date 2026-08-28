// Package metrics holds process-wide counters shared between the relay and
// the panel without coupling the two packages.
package metrics

import "sync/atomic"

var activeSessions atomic.Int64

// SessionStarted marks a tunnel session beginning.
func SessionStarted() { activeSessions.Add(1) }

// SessionEnded marks a tunnel session ending.
func SessionEnded() { activeSessions.Add(-1) }

// ActiveSessions returns the current live tunnel session count.
func ActiveSessions() int64 { return activeSessions.Load() }
