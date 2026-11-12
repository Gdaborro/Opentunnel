package server

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

type nativeH3DeadlineFixture struct {
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	writeDeadlineChanged        chan struct{}
	readErr, writeErr, flushErr error
	closedWrites                int
}

func (w *nativeH3DeadlineFixture) SetReadDeadline(t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.readDeadline = t
	return w.readErr
}
func (w *nativeH3DeadlineFixture) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writeDeadline = t
	if !t.IsZero() && !t.After(time.Now()) && w.writeDeadlineChanged != nil && w.closedWrites == 0 {
		close(w.writeDeadlineChanged)
		w.closedWrites++
	}
	return w.writeErr
}
func (w *nativeH3DeadlineFixture) Write(p []byte) (int, error) {
	if w.writeDeadlineChanged != nil {
		<-w.writeDeadlineChanged
		return 0, os.ErrDeadlineExceeded
	}
	return len(p), nil
}
func (w *nativeH3DeadlineFixture) FlushError() error { return w.flushErr }

func TestH3NativeReadAndWriteDeadlinesAreIndependentAndClearable(t *testing.T) {
	w := &nativeH3DeadlineFixture{}
	c := &h3ServerConn{Writer: w}
	read := time.Now().Add(time.Second)
	write := time.Now().Add(2 * time.Second)
	if err := c.SetReadDeadline(read); err != nil {
		t.Fatal(err)
	}
	if err := c.SetWriteDeadline(write); err != nil {
		t.Fatal(err)
	}
	if !w.readDeadline.Equal(read) || !w.writeDeadline.Equal(write) {
		t.Fatal("read/write deadline was not forwarded independently")
	}
	if err := c.SetDeadline(time.Time{}); err != nil || !w.readDeadline.IsZero() || !w.writeDeadline.IsZero() {
		t.Fatal("native setup deadlines were not cleared")
	}
	w.readErr = errors.New("fixture read deadline error")
	w.writeErr = errors.New("fixture write deadline error")
	if err := c.SetDeadline(write); !errors.Is(err, w.readErr) || !errors.Is(err, w.writeErr) {
		t.Fatal("native deadline errors were discarded")
	}
}

func TestH3CloseInterruptsBlockedNativeResponseWrite(t *testing.T) {
	r, body := io.Pipe()
	defer body.Close()
	w := &nativeH3DeadlineFixture{writeDeadlineChanged: make(chan struct{})}
	c := &h3ServerConn{Reader: r, Writer: w}
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("flow-controlled response")); done <- err }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed H3 write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("H3 flow-controlled write survived Close")
	}
	if err := c.Close(); err != nil {
		t.Fatal("second close was not idempotent", err)
	}
}

func TestH3FlushErrorsReachTheSession(t *testing.T) {
	w := &nativeH3DeadlineFixture{flushErr: errors.New("fixture flush failure")}
	c := &h3ServerConn{Writer: w}
	if n, err := c.Write([]byte("frame")); n != 5 || !errors.Is(err, w.flushErr) {
		t.Fatal("response flush failure was ignored")
	}
}

func TestH3CloseUnblocksPendingBodyRead(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	c := &h3ServerConn{Reader: r, Writer: io.Discard}
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 32)); done <- err }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed H3 read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("H3 body read stayed blocked after Close")
	}
}
