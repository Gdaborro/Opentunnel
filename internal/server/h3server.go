// h3server.go: the server end of the HTTP/3 tunnel path. The client speaks
// the tunnel protocol inside a streaming request; this shim couples the
// request body (client→server) and the flushed response body
// (server→client) into the net.Conn the session machinery expects.
//
// Production reads/writes use HTTP/3's native stream deadlines. This bounds
// both body reads and blocked response writes without detaching copy workers.
// The fallback read shim supports isolated tests/adapters without native
// deadlines, and never mutates a caller's buffer after a timed-out read.
package server

import (
	"errors"
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

	dlMu      sync.Mutex
	dlTimer   *time.Timer
	expired   chan struct{}
	once      sync.Once
	closeOnce sync.Once
	closed    chan struct{}
	closeErr  error
	writeMu   sync.Mutex
}

type h3DeadlineWriter interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type httpFlusher interface {
	Flush()
}

// SetDeadline arms (or clears, when t is zero) an absolute deadline; on
// expiry every Read fails with os.ErrDeadlineExceeded and the session
// machinery unwinds, releasing the guard slot.
func (c *h3ServerConn) SetDeadline(t time.Time) error {
	if native, ok := c.Writer.(h3DeadlineWriter); ok {
		return errors.Join(native.SetReadDeadline(t), native.SetWriteDeadline(t))
	}
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

func (c *h3ServerConn) SetReadDeadline(t time.Time) error {
	if native, ok := c.Writer.(h3DeadlineWriter); ok {
		return native.SetReadDeadline(t)
	}
	return c.SetDeadline(t)
}
func (c *h3ServerConn) SetWriteDeadline(t time.Time) error {
	if native, ok := c.Writer.(h3DeadlineWriter); ok {
		return native.SetWriteDeadline(t)
	}
	return c.SetDeadline(t)
}

func (c *h3ServerConn) Read(p []byte) (int, error) {
	c.dlMu.Lock()
	if c.closed == nil {
		c.closed = make(chan struct{})
	}
	closed := c.closed
	expired := c.expired
	c.dlMu.Unlock()
	select {
	case <-closed:
		return 0, net.ErrClosed
	case <-expired:
		return 0, errH3Deadline
	default:
	}
	if _, ok := c.Writer.(h3DeadlineWriter); ok {
		return c.Reader.Read(p)
	}
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	// Read into private storage: a deadline/close can return before the
	// underlying body read finishes. That worker must not mutate the caller's
	// reused buffer after Read has returned.
	buffer := make([]byte, len(p))
	go func() {
		n, err := c.Reader.Read(buffer)
		ch <- res{n, err}
	}()
	select {
	case r := <-ch:
		if r.n < 0 || r.n > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		copy(p, buffer[:r.n])
		return r.n, r.err
	case <-closed:
		return 0, net.ErrClosed
	case <-expired:
		// The pending read goroutine exits once the handler returns and
		// the request context cancels the stream underneath it.
		return 0, errH3Deadline
	}
}

func (c *h3ServerConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.dlMu.Lock()
	if c.closed == nil {
		c.closed = make(chan struct{})
	}
	closed := c.closed
	expired := c.expired
	c.dlMu.Unlock()
	select {
	case <-closed:
		return 0, net.ErrClosed
	case <-expired:
		return 0, errH3Deadline
	default:
	}
	n, err := c.Writer.Write(p)
	if err != nil {
		return n, err
	}
	if flusher, ok := c.Writer.(interface{ FlushError() error }); ok {
		err = flusher.FlushError()
	} else if c.Flusher != nil {
		// Per-frame flush: QUIC frames sit in buffers until flushed, and
		// interactive tunnel traffic must not wait for batch boundaries.
		c.Flusher.Flush()
	}
	return n, err
}

func (c *h3ServerConn) Close() error {
	c.closeOnce.Do(func() {
		c.dlMu.Lock()
		if c.closed == nil {
			c.closed = make(chan struct{})
		}
		close(c.closed)
		if c.dlTimer != nil {
			c.dlTimer.Stop()
			c.dlTimer = nil
		}
		c.dlMu.Unlock()
		// Abort blocked writes before waiting for smux/TLS shutdown. Closing
		// only the request body leaves a flow-controlled response write alive.
		if native, ok := c.Writer.(h3DeadlineWriter); ok {
			c.closeErr = native.SetWriteDeadline(time.Now())
		}
		if closer, ok := c.Reader.(io.Closer); ok {
			c.closeErr = errors.Join(c.closeErr, closer.Close())
		}
	})
	return c.closeErr
}

func (c *h3ServerConn) LocalAddr() net.Addr  { return dummyH3Addr{} }
func (c *h3ServerConn) RemoteAddr() net.Addr { return dummyH3Addr{} }

type dummyH3Addr struct{}

func (dummyH3Addr) Network() string { return "udp" }
func (dummyH3Addr) String() string  { return "h3" }
