package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"opentunnel/internal/protocol"
)

// MuxPool keeps warm authenticated tunnel sessions so every new browser
// connection reuses one TLS+WebSocket transport instead of paying a full
// handshake. Fewer connections also look more like ordinary browsing.
type MuxPool struct {
	factory     func(ctx context.Context) (net.Conn, error)
	maxSessions int
	dialTimeout time.Duration
	mu          sync.Mutex
	sessions    []*muxEntry
	next        int
}

type muxEntry struct{ sess *smux.Session }

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
	}
}

func (p *MuxPool) createSession(ctx context.Context) (*muxEntry, error) {
	conn, err := p.factory(ctx)
	if err != nil {
		return nil, err
	}
	sess, err := smux.Client(conn, protocol.MuxConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &muxEntry{sess: sess}, nil
}

// pick returns the next healthy entry round-robin, pruning dead sessions.
func (p *MuxPool) pick() *muxEntry {
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
			break
		}
	}
	go e.sess.Close()
}

// Open returns one multiplexed stream ready for a target exchange.
func (p *MuxPool) Open(ctx context.Context) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		e := p.pick()
		if e == nil {
			var err error
			e, err = p.createSession(ctx)
			if err != nil {
				return nil, err
			}
			p.add(e)
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
