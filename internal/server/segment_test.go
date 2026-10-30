package server

import (
	"bytes"
	"testing"
	"time"
)

// TestSegmentShaperSegmentsBulk: past the threshold a bulk stream must
// drain in bounded segments separated by jittered pauses, with every byte
// delivered.
func TestSegmentShaperSegmentsBulk(t *testing.T) {
	var sink bytes.Buffer
	var pauses []time.Duration
	p := segmentParams{
		threshold: 100,
		target:    time.Millisecond,
		minBudget: 64,
		maxBudget: 128,
		idleMin:   time.Millisecond,
		idleMax:   2 * time.Millisecond,
		onPause:   func(d time.Duration) { pauses = append(pauses, d) },
	}
	s := newSegmentShaper(&sink, 1_000_000, p)
	data := bytes.Repeat([]byte{'x'}, 1000)
	for off := 0; off < len(data); off += 64 {
		end := off + 64
		if end > len(data) {
			end = len(data)
		}
		n, err := s.Write(data[off:end])
		if err != nil || n != end-off {
			t.Fatalf("write chunk: n=%d err=%v", n, err)
		}
	}
	if sink.Len() != len(data) {
		t.Fatalf("bytes lost: %d != %d", sink.Len(), len(data))
	}
	if len(pauses) == 0 {
		t.Fatal("bulk stream never paused — segments not engaging")
	}
	for _, d := range pauses {
		if d < p.idleMin || d > p.idleMax {
			t.Fatalf("pause out of range: %v", d)
		}
	}
}

// TestSegmentShaperSmallTransfersStaySmooth: sub-threshold traffic passes
// straight through — interactive browsing must not stall in idle gaps.
func TestSegmentShaperSmallTransfersStaySmooth(t *testing.T) {
	var sink bytes.Buffer
	paused := false
	p := segmentParams{
		threshold: 10_000,
		target:    time.Millisecond,
		minBudget: 64,
		maxBudget: 128,
		idleMin:   time.Millisecond,
		idleMax:   time.Millisecond,
		onPause:   func(time.Duration) { paused = true },
	}
	s := newSegmentShaper(&sink, 1_000_000, p)
	if _, err := s.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if paused {
		t.Fatal("sub-threshold transfer must not pause — interactive stays smooth")
	}
	if sink.Len() != 4096 {
		t.Fatalf("bytes lost: %d", sink.Len())
	}
}
