package server

import (
	"net"
	"sync"
	"time"
)

// Guard throttles abusive clients without revealing that a proxy exists:
// over-limit and banned peers receive the same decoy page as everyone else.
type Guard struct {
	mu            sync.Mutex
	active        map[string]int // per-IP active tunnel count
	fails         map[string]*failRecord
	bans          map[string]time.Time // ip -> banned-until
	maxPerIP      int
	total         chan struct{}
	banBase       time.Duration
	banMax        time.Duration
	lastCleanupNs int64
}

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
	return &Guard{
		active:        make(map[string]int),
		fails:         make(map[string]*failRecord),
		bans:          make(map[string]time.Time),
		maxPerIP:      maxPerIP,
		total:         make(chan struct{}, maxTotal),
		banBase:       banBase,
		banMax:        banMax,
		lastCleanupNs: time.Now().UnixNano(),
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
	g.mu.Lock()
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
	g.active[ip]++
	g.mu.Unlock()

	select {
	case g.total <- struct{}{}:
	default:
		g.releaseSlot(ip)
		return nil
	}
	return func() { g.releaseSlot(ip) }
}

func (g *Guard) releaseSlot(ip string) {
	select {
	case <-g.total:
	default:
	}
	g.mu.Lock()
	g.active[ip]--
	if g.active[ip] <= 0 {
		delete(g.active, ip)
	}
	g.mu.Unlock()
}

// Punish records a failed handshake and escalates the peer's ban.
func (g *Guard) Punish(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	rec := g.fails[ip]
	if rec == nil || now.Sub(rec.lastFail) > g.banMax {
		rec = &failRecord{}
		g.fails[ip] = rec
	}
	rec.count++
	rec.lastFail = now

	// Three strikes before any ban: one or two typos must not lock out a
	// legitimate user sharing the IP.
	const strikeThreshold = 3
	if rec.count >= strikeThreshold {
		d := g.banBase << uint(minInt(rec.count-strikeThreshold, 20)) // 30s, 60s, 120s … capped
		if d > g.banMax {
			d = g.banMax
		}
		g.bans[ip] = now.Add(d)
	}

	// Opportunistic cleanup roughly every ban cycle.
	if now.UnixNano()-g.lastCleanupNs > int64(g.banMax) {
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
