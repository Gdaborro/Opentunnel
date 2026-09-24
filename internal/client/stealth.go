package client

import (
	"math/rand"
	"sync/atomic"
	"time"
)

// hostileFlag latches when the adaptive dialer concludes the network
// intercepts TLS (every ws tier fails certificate pinning). Beacons consult
// it to stretch themselves; cleared on the first clean ws-tls dial.
var hostileFlag atomic.Bool

// thinFlag marks a shaped uplink: bulk background work (update downloads,
// throughput re-probes) stands down while interactive traffic continues.
// Set on a shaping verdict, cleared on the first healthy probe.
var thinFlag atomic.Bool

// HostileMode reports whether the client believes it runs on a hostile
// (TLS-intercepting) network.
func HostileMode() bool { return hostileFlag.Load() }

func setHostileMode(on bool) { hostileFlag.Store(on) }

// ThinMode reports whether bulk background work should stand down.
func ThinMode() bool { return thinFlag.Load() }

// SetThinMode sets thin mode (shaping verdict on/off).
func SetThinMode(on bool) { thinFlag.Store(on) }

// jittered returns d plus up to 50% extra, so periodic beacons (status
// polls, health reports) never fire on an exact metronome an analyst can
// correlate. On hostile networks the base is quadrupled first.
func jittered(d time.Duration) time.Duration {
	if HostileMode() {
		d *= 4
	}
	if d <= 0 {
		return 0
	}
	return d + time.Duration(rand.Int63n(int64(d)/2+1))
}
