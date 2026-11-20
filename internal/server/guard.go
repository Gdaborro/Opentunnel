package server

import (
	"net"
	"sync"
	"time"
)

// Guard throttles abusive clients without revealing that a proxy exists:
// over-limit and banned peers receive the same decoy page as everyone else.
type Guard struct {
	mu              sync.Mutex
	active          map[string]int // per-IP active tunnel count
	fails           map[string]*failRecord
	bans            map[string]time.Time // ip -> banned-until
	maxPerIP        int
	total           chan struct{}
	banBase         time.Duration
	banMax          time.Duration
	lastCleanupNs   int64
	droppedSources  uint64
	overflowUntil   time.Time
	overflowStrikes int

	// tokenActive bounds concurrent sessions per device identity for
	// peers arriving over loopback (the ssh tier's forward path): per-IP
	// caps and bans do not apply to loopback, so an identity must not be
	// able to exhaust the relay through that exemption.
	tokenActive map[string]int
}

// maxSessionsPerToken caps concurrent authenticated sessions per device
// (loopback arrivals). 4 covers the mux pool's dial churn with room.
const maxSessionsPerToken = 8

const maxGuardSources = 8192

type failRecord struct {
	count    int
	lastFail time.Time
}

// DefaultGuard returns sensible production limits.
func DefaultGuard() *Guard {
	return NewGuard(16, 1024, 30*time.Second, 10*time.Minute)
}

// NewGuard builds a Guard allowing maxPerIP concurrent tunnels per source IP
// and maxTotal overall; authentication failures trigger escalating bans from
// banBase up to banMax.
func NewGuard(maxPerIP, maxTotal int, banBase, banMax time.Duration) *Guard {
	maxPerIP = max(1, min(maxPerIP, 1024))
	maxTotal = max(1, min(maxTotal, 65536))
	if banBase <= 0 {
		banBase = time.Second
	}
	if banMax < banBase {
		banMax = banBase
	}
	return &Guard{
		active:        make(map[string]int),
		fails:         make(map[string]*failRecord),
		bans:          make(map[string]time.Time),
		tokenActive:   make(map[string]int),
		maxPerIP:      maxPerIP,
		total:         make(chan struct{}, maxTotal),
		banBase:       banBase,
		banMax:        banMax,
		lastCleanupNs: time.Now().UnixNano(),
	}
}

// AcquireTokenSession admits one session for a device identity arriving
// over loopback. The returned release function must be called when the
// session finishes; release==nil means over the per-identity cap.
func (g *Guard) AcquireTokenSession(token string) (release func()) {
	if token == "" {
		return func() {}
	}
	g.mu.Lock()
	if len(token) > 1024 || (g.tokenActive[token] == 0 && len(g.tokenActive) >= cap(g.total)) || g.tokenActive[token] >= maxSessionsPerToken {
		g.mu.Unlock()
		return nil
	}
	g.tokenActive[token]++
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if n := g.tokenActive[token]; n <= 1 {
				delete(g.tokenActive, token)
			} else {
				g.tokenActive[token] = n - 1
			}
			g.mu.Unlock()
		})
	}
}

// addrHost extracts the IP portion of a "host:port" string or net.Addr.
func addrHost(v any) string {
	switch a := v.(type) {
	case net.Addr:
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return a.String()
		}
		return host
	case string:
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return a
		}
		return host
	default:
		return ""
	}
}

// Acquire admits an inbound request if the peer is clean and under limits.
// The returned release function must be called when the tunnel finishes;
// release==nil means denied (serve the decoy page instead).
func (g *Guard) Acquire(ip string) (release func()) {
	if isLoopbackIP(ip) {
		// Loopback cannot be rate-limited by source identity (all forwarded
		// peers share it), but must still consume the global setup budget.
		select {
		case g.total <- struct{}{}:
			var once sync.Once
			return func() { once.Do(func() { <-g.total }) }
		default:
			return nil
		}
	}
	g.mu.Lock()
	if ip == "" || len(ip) > 128 {
		g.mu.Unlock()
		return nil
	}
	now := time.Now()
	g.cleanupLocked(now)
	_, trackedBan := g.bans[ip]
	if g.overflowUntil.After(now) && g.active[ip] == 0 && g.fails[ip] == nil && !trackedBan {
		// Source-map saturation must fail closed for otherwise unknown
		// sources; active and recently tracked sources are unaffected.
		g.mu.Unlock()
		return nil
	}
	if until, banned := g.bans[ip]; banned {
		if time.Now().Before(until) {
			g.mu.Unlock()
			return nil
		}
		delete(g.bans, ip)
	}
	if g.active[ip] >= g.maxPerIP {
		g.mu.Unlock()
		return nil
	}
	select {
	case g.total <- struct{}{}:
	default:
		g.mu.Unlock()
		return nil
	}
	g.active[ip]++
	g.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { g.releaseSlot(ip) }) }
}

func (g *Guard) releaseSlot(ip string) {
	select {
	case <-g.total:
	default:
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active[ip]--
	if g.active[ip] <= 0 {
		delete(g.active, ip)
	}
}

// BanIP applies an explicit temporary ban (sentinel L2 response). Banned
// peers see the decoy page like everyone else — the ban stays invisible.
func (g *Guard) BanIP(ip string, d time.Duration) {
	if ip == "" || len(ip) > 128 || d <= 0 || isLoopbackIP(ip) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanupLocked(time.Now())
	if _, exists := g.bans[ip]; !exists && len(g.bans) >= maxGuardSources {
		g.noteOverflowLocked(time.Now(), d)
		return
	}
	until := time.Now().Add(d)
	if cur, ok := g.bans[ip]; !ok || cur.Before(until) {
		g.bans[ip] = until
	}
}

// Punish records a failed handshake and escalates the peer's ban.
func (g *Guard) Punish(ip string) {
	if ip == "" || len(ip) > 128 || isLoopbackIP(ip) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	g.cleanupLocked(now)
	rec := g.fails[ip]
	if rec == nil || now.Sub(rec.lastFail) > g.banMax {
		if rec == nil && len(g.fails) >= maxGuardSources {
			g.noteOverflowLocked(now, g.banBase)
			return
		}
		rec = &failRecord{}
		g.fails[ip] = rec
	}
	rec.count = min(rec.count+1, 23)
	rec.lastFail = now

	// Three strikes before any ban: one or two typos must not lock out a
	// legitimate user sharing the IP.
	const strikeThreshold = 3
	if rec.count >= strikeThreshold {
		d := g.banBase
		for step := 0; step < minInt(rec.count-strikeThreshold, 20); step++ {
			if d >= g.banMax || d > g.banMax/2 {
				d = g.banMax
				break
			}
			d *= 2
		}
		if _, exists := g.bans[ip]; exists || len(g.bans) < maxGuardSources {
			g.bans[ip] = now.Add(d)
		} else {
			g.noteOverflowLocked(now, d)
		}
	}

}

func (g *Guard) noteOverflowLocked(now time.Time, d time.Duration) {
	if d <= 0 {
		d = g.banBase
	}
	g.droppedSources++
	g.overflowStrikes = min(g.overflowStrikes+1, 23)
	until := now.Add(d)
	if g.overflowUntil.Before(until) {
		g.overflowUntil = until
	}
}

func (g *Guard) DroppedSources() uint64 { g.mu.Lock(); defer g.mu.Unlock(); return g.droppedSources }

// One bounded sweep per minute, not a full-map scan per overflowing source.
// Admission is already capped globally; overflow cannot allocate more state.
func (g *Guard) cleanupLocked(now time.Time) {
	if !g.overflowUntil.IsZero() && !now.Before(g.overflowUntil) {
		g.overflowStrikes = 0
	}
	if now.UnixNano()-g.lastCleanupNs > int64(min(g.banMax, time.Minute)) {
		for k, t := range g.bans {
			if now.After(t) {
				delete(g.bans, k)
			}
		}
		for k, fr := range g.fails {
			if now.Sub(fr.lastFail) > g.banMax {
				delete(g.fails, k)
			}
		}
		g.lastCleanupNs = now.UnixNano()
	}
}

func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
