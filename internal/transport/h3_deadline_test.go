package transport

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// blockingReader never returns: it models a peer that accepted the stream
// and went silent (the exact shape the no-op deadline used to trap).
type blockingReader struct{ ch chan struct{} }

func newBlockingReader() *blockingReader { return &blockingReader{ch: make(chan struct{})} }
func (b *blockingReader) Read(p []byte) (int, error) {
	<-b.ch
	return 0, io.EOF
}
func (b *blockingReader) Close() error { close(b.ch); return nil }

// TestH3ClientDeadlineForceCloses: an armed deadline must interrupt a
// blocked read within its window instead of hanging forever (audit round
// three, N-4).
func TestH3ClientDeadlineForceCloses(t *testing.T) {
	br := newBlockingReader()
	pr, pw := io.Pipe()
	_ = pr // the writer half stands in for the request body side
	_, cancel := context.WithCancel(context.Background())

	c := &h3ClientConn{
		pw:     pw,
		body:   br,
		tr:     &http3.Transport{}, // Close on a never-used transport is a no-op
		cancel: cancel,
	}
	if err := c.SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	buf := make([]byte, 8)
	_, err := c.Read(buf)
	if err == nil {
		t.Fatal("read must fail after the deadline")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline too slow: %v", elapsed)
	}
}

// TestH3ClientClearedDeadlineDoesNotClose: clearing the deadline (the mux
// factory does this after auth) must disable the timer.
func TestH3ClientClearedDeadlineDoesNotClose(t *testing.T) {
	br := newBlockingReader()
	pr, pw := io.Pipe()
	_ = pr

	c := &h3ClientConn{pw: pw, body: br, tr: &http3.Transport{}, cancel: func() {}}
	_ = c.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_ = c.SetDeadline(time.Time{}) // clear, as muxSessionFactory does
	time.Sleep(300 * time.Millisecond)
	// The body must still be open: closing it would have sent on br.ch.
	select {
	case <-br.ch:
		t.Fatal("cleared deadline still fired")
	default:
	}
	_ = c.Close() // cleanup
}
