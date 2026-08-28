package server

import (
	"bytes"
	"io"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// plainReader hides WriteTo so CopyBuffer actually chunks through the buffer.
type plainReader struct{ r io.Reader }

func (p *plainReader) Read(b []byte) (int, error) { return p.r.Read(b) }

// TestLimitedWriterPaces checks the QoS writer actually throttles: 64 KiB
// through a 64 KiB/s bucket must take noticeably longer than uncapped.
func TestLimitedWriterPaces(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, 64*1024)

	var sink bytes.Buffer
	// burst == io.Copy's 32KiB chunk: first chunk passes on the burst,
	// the second must wait ~500ms for tokens at 64KiB/s.
	lim := rate.NewLimiter(rate.Limit(64*1024), 32*1024)
	w := &limitedWriter{w: &sink, lim: lim}

	start := time.Now()
	if _, err := io.CopyBuffer(w, &plainReader{bytes.NewReader(data)}, make([]byte, 32*1024)); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Fatalf("64KiB at 64KiB/s finished in %v — limiter not pacing", elapsed)
	}
	if sink.Len() != len(data) {
		t.Fatalf("wrote %d bytes, want %d", sink.Len(), len(data))
	}
}
