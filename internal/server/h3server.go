// h3server.go: the server end of the HTTP/3 tunnel path. The client speaks
// the tunnel protocol inside a streaming request; this shim couples the
// request body (client→server) and the flushed response body
// (server→client) into the net.Conn the session machinery expects.
//
// Deadlines are REAL here (audit round three, N-4): the 15s handshake
// deadline in handleSession used to evaporate on a no-op shim, letting a
// client that never sends protocol bytes pin a goroutine and a guard slot
// indefinitely. Reads race the request body against the deadline channel;
// the request context cancels when the handler returns, which unblocks
// any pending body read and lets the read goroutine exit.
package server

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var errH3Deadline = os.ErrDeadlineExceeded

// h3ServerConn adapts the HTTP/3 request/response pair into a net.Conn.
type h3ServerConn struct {
	Reader  io.Reader
	Writer  io.Writer
	Flusher httpFlusher

	dlMu    sync.Mutex
	dlTimer *time.Timer
	expired chan struct{}
	once    sync.Once
}

type httpFlusher interface {
	Flush()
}

// SetDeadline arms (or clears, when t is zero) an absolute deadline; on
// expiry every Read fails with os.ErrDeadlineExceeded and the session
// machinery unwinds, releasing the guard slot.
func (c *h3ServerConn) SetDeadline(t time.Time) error {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	if c.dlTimer != nil {
		c.dlTimer.Stop()
		c.dlTimer = nil
	}
	if t.IsZero() {
		return nil
	}
	if c.expired == nil {
		c.expired = make(chan struct{})
	}
	d := time.Until(t)
	if d <= 0 {
		c.once.Do(func() { close(c.expired) })
		return nil
	}
	c.dlTimer = time.AfterFunc(d, func() {
		c.once.Do(func() { close(c.expired) })
	})
	return nil
}

func (c *h3ServerConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *h3ServerConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *h3ServerConn) Read(p []byte) (int, error) {
	select {
	case <-c.expired:
		return 0, errH3Deadline
	default:
	}
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := c.Reader.Read(p)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-c.expired:
		// The pending read goroutine exits once the handler returns and
		// the request context cancels the stream underneath it.
		return 0, errH3Deadline
	}
}

func (c *h3ServerConn) Write(p []byte) (int, error) {
	select {
	case <-c.expired:
		return 0, errH3Deadline
	default:
	}
	n, err := c.Writer.Write(p)
	if c.Flusher != nil {
		// Per-frame flush: QUIC frames sit in buffers until flushed, and
		// interactive tunnel traffic must not wait for batch boundaries.
		c.Flusher.Flush()
	}
	return n, err
}

func (c *h3ServerConn) Close() error {
	c.dlMu.Lock()
	if c.dlTimer != nil {
		c.dlTimer.Stop()
		c.dlTimer = nil
	}
	c.dlMu.Unlock()
	return nil
}

func (c *h3ServerConn) LocalAddr() net.Addr  { return dummyH3Addr{} }
func (c *h3ServerConn) RemoteAddr() net.Addr { return dummyH3Addr{} }

type dummyH3Addr struct{}

func (dummyH3Addr) Network() string { return "udp" }
func (dummyH3Addr) String() string  { return "h3" }
