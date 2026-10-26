package client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// echoSessionFactory builds a factory whose far end runs a real smux
// server echoing stream bytes — byte-rotation needs wire-real traffic.
func echoSessionFactory(dials *int) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		*dials++
		c1, c2 := net.Pipe()
		go func() {
			sess, err := smux.Server(c2, smux.DefaultConfig())
			if err != nil {
				return
			}
			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					return
				}
				go func(s *smux.Stream) {
					_, _ = io.Copy(s, s)
					s.Close()
				}(stream)
			}
		}()
		return c1, nil
	}
}

// TestMuxRotatesByBytes: no single session may carry gigabytes — byte
// caps make every flow read as a large file copy, not an infinite pipe.
// A pool with a tiny cap must retire the fat session and dial a new one.
func TestMuxRotatesByBytes(t *testing.T) {
	dials := 0
	p := newMuxPool(echoSessionFactory(&dials), 4, 5*time.Second)
	p.maxAge = time.Hour // keep time rotation out of the picture
	p.maxBytes = 8192

	write := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stream, err := p.Open(ctx)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer stream.Close()
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = byte(i)
		}
		if _, err := stream.Write(buf); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Fatalf("read echo: %v", err)
		}
	}

	write()
	write() // ~16KB+ overhead over the wire: past the 8KB cap
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if dials >= 2 {
			return // fat session retired, fresh one dialed
		}
		time.Sleep(50 * time.Millisecond)
		p.retire()
		write()
	}
	t.Fatalf("byte rotation never fired: dials = %d", dials)
}
