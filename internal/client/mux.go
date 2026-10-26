package client

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"

	"opentunnel/internal/protocol"
)

// MuxPool keeps warm authenticated tunnel sessions so every new browser
// connection reuses one TLS+WebSocket transport instead of paying a full
// handshake. Fewer connections also look more like ordinary browsing.
// softCapStreams caps how many concurrent streams pile onto one session
// before the pool spills over to a fresh session. The relay drops streams
// past its per-session cap (currently 256); without spillover every retry
// lands on the same saturated session and the failure feeds itself — mass
// EOFs under page-load bursts. 192 keeps headroom under the relay cap.
const softCapStreams = 192

// rotationWindow bounds a session's useful life: sessions older than
// maxAge stop taking new streams (graceful drain) so no single TLS flow
// lives for hours — the signature a human spots first in a flow table.
// Draining sessions close once empty or past maxAge+maxDrain, so long
// downloads are never cut (unlike a hard kill).
const (
	rotationAge = 25 * time.Minute
	maxDrain    = 10 * time.Minute
	sweepEvery  = 5 * time.Minute
)

// rotationBytesBase bounds a session's total transfer: no single flow
// should carry gigabytes either — browsing sessions never do, and a
// multi-GB SSH stream is a tunneling signature on its own. ~120-200 MB
// reads as a large file copy (git/rsync/SFTP), the most ordinary heavy
// SSH pattern there is. Randomized per session like the age window.
const rotationBytesBase = 160 << 20

type MuxPool struct {
	factory     func(ctx context.Context) (net.Conn, error)
	maxSessions int
	dialTimeout time.Duration
	maxAge      time.Duration // per-session rotation age (tests shrink this)
	maxBytes    int64         // per-session rotation byte cap (0 = default; tests shrink this)
	softCap     int           // spill over to a new session past this many streams (tests shrink this)
	suggestAge  time.Duration // self-tuned rotation age (0 = follow maxAge)
	mu          sync.Mutex
	sessions    []*muxEntry
	next        int
	sweeper     bool

	// dialing guards session creation so a page-load burst (dozens of
	// domains at once) mints at most ONE full SSH+WS+auth handshake at a
	// time; the rest wait briefly for it to land and then reuse it instead
	// of stampeding the relay with parallel handshakes.
	dialing bool
	dialCh  chan struct{} // closed when the in-flight dial finishes
}

type muxEntry struct {
	sess        *smux.Session
	born        time.Time
	retireAt    time.Time
	retireBytes int64
	bytes       *atomic.Int64 // wire bytes crossing the underlying conn
	draining    bool
}

// minRotationAge floors self-tuning: rotation never gets twitchier than this.
const minRotationAge = 5 * time.Minute

// effAge returns the rotation age in force: the configured maxAge possibly
// reduced by self-tuning (never increased — quotas only ever cut sessions
// short, so adaptation only ever shortens).
func (p *MuxPool) effAge() time.Duration {
	base := p.maxAge
	if base <= 0 {
		base = rotationAge
	}
	if p.suggestAge > 0 && p.suggestAge < base {
		return p.suggestAge
	}
	return base
}

// noteDeath folds one session death into self-tuning. Premature deaths
// (forced kills well under the effective age — TTL quotas, resets) shrink
// rotation fast; healthy retirements grow it back toward configured, so the
// pool converges instead of ratcheting. Callers hold p.mu.
func (p *MuxPool) noteDeath(born time.Time) {
	if born.IsZero() {
		return
	}
	age := time.Since(born)
	if age < p.effAge()-time.Minute {
		if s := age - time.Minute; s > minRotationAge {
			p.suggestAge = s
		} else {
			p.suggestAge = minRotationAge
		}
		return
	}
	if p.suggestAge > 0 {
		base := p.maxAge
		if base <= 0 {
			base = rotationAge
		}
		p.suggestAge += 5 * time.Minute
		if p.suggestAge >= base {
			p.suggestAge = 0 // back to configured
		}
	}
}

func newMuxPool(factory func(ctx context.Context) (net.Conn, error), maxSessions int, dialTimeout time.Duration) *MuxPool {
	if maxSessions < 1 {
		maxSessions = 1
	}
	if dialTimeout <= 0 {
		dialTimeout = 15 * time.Second
	}
	return &MuxPool{
		factory:     factory,
		maxSessions: maxSessions,
		dialTimeout: dialTimeout,
		maxAge:      rotationAge,
		maxBytes:    rotationBytesBase,
		softCap:     softCapStreams,
	}
}

// countingConn tallies wire bytes crossing the session's underlying
// transport so byte-based rotation sees what the network sees.
type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	k, err := c.Conn.Read(p)
	c.n.Add(int64(k))
	return k, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	k, err := c.Conn.Write(p)
	c.n.Add(int64(k))
	return k, err
}

func (p *MuxPool) createSession(ctx context.Context) (*muxEntry, error) {
	conn, err := p.factory(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	p.mu.Lock()
	maxAge := p.effAge()
	maxBytes := p.maxBytes
	p.mu.Unlock()
	var extra time.Duration
	if maxAge > 0 {
		extra = time.Duration(rand.Int63n(int64(maxAge) / 4))
	}
	if maxBytes <= 0 {
		maxBytes = rotationBytesBase
	}
	// Slack defeats metronomic rotation: sessions retire unpredictably
	// inside the window, never on a schedule — and byte caps drift so
	// flow sizes never repeat exactly.
	retireBytes := maxBytes + rand.Int63n(maxBytes/4)
	counter := &atomic.Int64{}
	sess, err := smux.Client(&countingConn{Conn: conn, n: counter}, muxConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &muxEntry{
		sess:        sess,
		born:        now,
		bytes:       counter,
		retireBytes: retireBytes,
		// Slack defeats metronomic rotation: sessions retire
		// unpredictably inside the window, never on a schedule.
		retireAt: now.Add(maxAge).Add(extra),
	}, nil
}

// retireLocked marks expired sessions draining and drops finished ones,
// returning sessions to close OUTSIDE the pool lock. Draining sessions take
// no new streams (pick skips them); in-flight streams finish undisturbed
// until empty or past the hard cap, so rotation never cuts a download.
func (p *MuxPool) retireLocked(now time.Time) (dead []*muxEntry) {
	alive := p.sessions[:0]
	for _, e := range p.sessions {
		if e.sess.IsClosed() {
			continue
		}
		if e.draining {
			if e.sess.NumStreams() == 0 || now.After(e.retireAt.Add(maxDrain)) {
				p.noteDeath(e.born)
				dead = append(dead, e)
				continue
			}
			alive = append(alive, e)
			continue
		}
		if now.After(e.retireAt) || (e.bytes != nil && e.bytes.Load() > e.retireBytes) {
			e.draining = true
		}
		alive = append(alive, e)
	}
	p.sessions = alive
	if len(p.sessions) == 0 {
		p.next = 0
	}
	return dead
}

// retire applies retireLocked and closes reaped sessions outside the lock.
func (p *MuxPool) retire() {
	p.mu.Lock()
	dead := p.retireLocked(time.Now())
	p.mu.Unlock()
	for _, e := range dead {
		_ = e.sess.Close()
	}
}

// sweep retires on a timer so even idle pools (keepalive-only flows, the
// quietest long-lived signature) rotate. One goroutine per pool; pools live
// as long as the process. Phase and interval are randomized per pool: a
// whole fleet sweeping on the same wall-clock cadence would itself be a
// correlatable signature.
func (p *MuxPool) sweep() {
	p.mu.Lock()
	if p.sweeper {
		p.mu.Unlock()
		return
	}
	p.sweeper = true
	p.mu.Unlock()
	go func() {
		time.Sleep(time.Duration(rand.Int63n(int64(sweepEvery))))
		for {
			time.Sleep(sweepEvery + time.Duration(rand.Int63n(int64(time.Minute))))
			p.retire()
		}
	}()
}

// muxConfig clones the shared smux parameters with a jittered keepalive:
// an exact 20 s heartbeat from every session is a correlatable beacon.
func muxConfig() *smux.Config {
	cfg := protocol.MuxConfig()
	cfg.KeepAliveInterval += time.Duration(rand.Int63n(int64(10 * time.Second)))
	return cfg
}

// overCap reports whether a session already carries enough streams that
// new ones should spill over to a fresher session (see softCapStreams).
func overCap(e *muxEntry, cap int) bool {
	if cap <= 0 {
		return false
	}
	return e.sess.NumStreams() >= cap
}

// pick returns the next healthy entry round-robin, pruning dead sessions.
// Draining (retired) sessions stay listed until empty but take no new
// streams; retire() runs first so expiry is enforced on activity too.
func (p *MuxPool) pick() *muxEntry {
	p.retire()
	p.mu.Lock()
	defer p.mu.Unlock()
	alive := p.sessions[:0]
	var chosen *muxEntry
	for i := 0; i < len(p.sessions); i++ {
		e := p.sessions[(p.next+i)%len(p.sessions)]
		if e.sess.IsClosed() {
			continue
		}
		alive = append(alive, e)
		if e.draining || overCap(e, p.softCap) {
			continue
		}
		if chosen == nil {
			chosen = e
			p.next = (p.next + i + 1) % maxInt(1, len(p.sessions))
		}
	}
	p.sessions = alive
	if len(p.sessions) == 0 {
		p.next = 0
	}
	return chosen
}

func (p *MuxPool) add(e *muxEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.addLocked(e)
}

func (p *MuxPool) addLocked(e *muxEntry) {
	if len(p.sessions) >= p.maxSessions {
		// Replace the oldest; smux keepalive will retire it cleanly.
		old := p.sessions[0]
		go old.sess.Close()
		p.sessions = p.sessions[1:]
	}
	p.sessions = append(p.sessions, e)
	p.next = len(p.sessions) - 1
}

func (p *MuxPool) drop(e *muxEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, x := range p.sessions {
		if x == e {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			p.noteDeath(e.born)
			break
		}
	}
	go e.sess.Close()
}

// Open returns one multiplexed stream ready for a target exchange.
//
// Burst behavior: with no live session, at most one handshake runs at a
// time. Concurrent openers wait on the in-flight dial (bounded by ctx and a
// cap); when it lands they all reuse the new session instead of queueing
// their own handshakes. If the wait runs long (hung dial), a caller may
// break out and dial itself as a last resort.
func (p *MuxPool) Open(ctx context.Context) (net.Conn, error) {
	const waiterCap = 10 * time.Second
	p.sweep() // idle pools rotate too (no-op after the first call)
	for attempt := 0; attempt < 2; attempt++ {
		e := p.pick()
		if e == nil {
			var err error
			e, err = p.getOrDial(ctx, waiterCap)
			if err != nil {
				return nil, err
			}
		}
		stream, err := e.sess.OpenStream()
		if err == nil {
			return stream, nil
		}
		if errors.Is(err, smux.ErrGoAway) || e.sess.IsClosed() {
			p.drop(e)
			continue // retry with a fresh session
		}
		p.drop(e)
		return nil, err
	}
	return nil, errors.New("client: mux pool exhausted")
}

// getOrDial returns a usable session, dialing one if none exists. Only one
// caller dials at a time; the rest wait for its result and reuse it.
func (p *MuxPool) getOrDial(ctx context.Context, waiterCap time.Duration) (*muxEntry, error) {
	deadline := time.Now().Add(waiterCap)
	for {
		p.mu.Lock()
		// A session appeared while we waited for the lock (skip draining
		// and over-cap ones: retired sessions take no new streams).
		for _, e := range p.sessions {
			if !e.sess.IsClosed() && !e.draining && !overCap(e, p.softCap) {
				p.mu.Unlock()
				return e, nil
			}
		}
		if !p.dialing {
			// We're the dialer.
			p.dialing = true
			ch := make(chan struct{})
			p.dialCh = ch
			p.mu.Unlock()
			entry, err := p.createSession(ctx)
			p.mu.Lock()
			p.dialing = false
			if p.dialCh == ch {
				close(ch)
				p.dialCh = nil
			}
			if err != nil {
				p.mu.Unlock()
				return nil, err
			}
			p.addLocked(entry)
			p.mu.Unlock()
			return entry, nil
		}
		// Someone else is dialing: wait for them, bounded.
		ch := p.dialCh
		p.mu.Unlock()
		select {
		case <-ch:
			// loop: pick up the session (or become the dialer if it failed)
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Until(deadline)):
			// The in-flight dial looks hung — dial one ourselves.
			entry, err := p.createSession(ctx)
			if err != nil {
				return nil, err
			}
			p.add(entry)
			return entry, nil
		}
	}
}

// NumSessions reports the count of live mux sessions (for status output).
func (p *MuxPool) NumSessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.sessions {
		if !e.sess.IsClosed() {
			n++
		}
	}
	return n
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
