// h3server.go: the server end of the HTTP/3 tunnel path. The client speaks
// the tunnel protocol inside a streaming request; this shim couples the
// request body (client→server) and the flushed response body
// (server→client) into the net.Conn the session machinery expects.
package server

import (
	"io"
	"net"
	"time"
)

// h3ServerConn adapts the HTTP/3 request/response pair into a net.Conn.
// Deadlines are no-ops (the ssh tier's channel shim does the same): the
// inner protocol carries its own timeouts and QUIC enforces idle limits.
type h3ServerConn struct {
	Reader  io.Reader
	Writer  io.Writer
	Flusher httpFlusher
}

type httpFlusher interface {
	Flush()
}

func (c *h3ServerConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

func (c *h3ServerConn) Write(p []byte) (int, error) {
	n, err := c.Writer.Write(p)
	if c.Flusher != nil {
		// Per-frame flush: QUIC frames sit in buffers until flushed, and
		// interactive tunnel traffic must not wait for batch boundaries.
		c.Flusher.Flush()
	}
	return n, err
}

func (c *h3ServerConn) Close() error { return nil }

func (c *h3ServerConn) LocalAddr() net.Addr                { return dummyH3Addr{} }
func (c *h3ServerConn) RemoteAddr() net.Addr               { return dummyH3Addr{} }
func (c *h3ServerConn) SetDeadline(t time.Time) error      { return nil }
func (c *h3ServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *h3ServerConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyH3Addr struct{}

func (dummyH3Addr) Network() string { return "udp" }
func (dummyH3Addr) String() string  { return "h3" }
