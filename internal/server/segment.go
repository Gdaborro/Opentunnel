// segment.go: traffic-shape mimicry for ssh-tier bulk transfers.
//
// A capped-but-flat transfer still reads as a feed: constant line-rate
// bytes with no human/app structure. Real heavy traffic on the wire —
// video streaming above all — arrives in segments: a multi-second burst
// while the player fills its buffer, then a quiet gap while it plays out.
//
// segmentShaper reproduces that cadence on the ssh tier (the tier where
// flow shape matters most, because many devices fan into one relay IP on
// port 22). Small transfers pass through untouched; once a stream crosses
// a bulk threshold it drains segment-sized bursts at the rate cap with a
// jittered idle gap between them. It never exceeds the cap (the rate
// limiter sits beneath it) and never drops bytes — the only cost is the
// bounded idle gaps.
package server

import (
	"io"
	"math/rand"
	"time"
)

// segmentParams tunes the shaper. Defaults are the production shape;
// tests shrink the windows.
type segmentParams struct {
	threshold int64         // bytes on a stream before segments engage
	target    time.Duration // nominal segment drain duration
	minBudget int64         // segment size clamp (bytes)
	maxBudget int64
	idleMin   time.Duration
	idleMax   time.Duration
	onPause   func(time.Duration) // test hook; nil in production
}

func defaultSegmentParams() segmentParams {
	return segmentParams{
		threshold: 1 << 20, // 1 MiB: interactive browsing stays smooth
		target:    3 * time.Second,
		minBudget: 1 << 20,
		maxBudget: 8 << 20,
		idleMin:   800 * time.Millisecond,
		idleMax:   2400 * time.Millisecond,
	}
}

type segmentShaper struct {
	w      io.Writer
	perSec int64 // rate cap used to size segments (bytes/sec)
	params segmentParams

	written int64
	budget  int64 // bytes remaining in the current segment
}

func newSegmentShaper(w io.Writer, perSec int64, p segmentParams) *segmentShaper {
	if p.threshold <= 0 {
		p.threshold = 1
	}
	if p.target <= 0 {
		p.target = time.Second
	}
	if p.minBudget <= 0 {
		p.minBudget = 1
	}
	if p.maxBudget < p.minBudget {
		p.maxBudget = p.minBudget
	}
	if p.idleMax < p.idleMin {
		p.idleMax = p.idleMin
	}
	return &segmentShaper{w: w, perSec: perSec, params: p}
}

// nextBudget picks the next segment's size: the bytes drained in ~target
// at the cap, clamped, then jittered ±25% so segment sizes never repeat
// exactly.
func (s *segmentShaper) nextBudget() int64 {
	b := int64(float64(s.perSec) * s.params.target.Seconds())
	if b < s.params.minBudget {
		b = s.params.minBudget
	}
	if b > s.params.maxBudget {
		b = s.params.maxBudget
	}
	j := b / 4
	if j > 0 {
		b += rand.Int63n(2*j+1) - j
	}
	if b < 1 {
		b = 1
	}
	return b
}

// pause idles a jittered gap, then opens the next segment.
func (s *segmentShaper) pause() {
	idle := s.params.idleMin
	if span := s.params.idleMax - s.params.idleMin; span > 0 {
		idle += time.Duration(rand.Int63n(int64(span)))
	}
	if s.params.onPause != nil {
		s.params.onPause(idle)
	}
	time.Sleep(idle)
	s.budget = s.nextBudget()
}

// Write implements io.Writer. Bytes flow straight through until the bulk
// threshold; after that, each segment drains up to its budget and then
// the shaper idles before opening the next one.
func (s *segmentShaper) Write(p []byte) (int, error) {
	total := len(p)
	off := 0
	for off < total {
		if s.written >= s.params.threshold {
			if s.budget <= 0 {
				s.pause()
			}
			chunk := int64(total - off)
			if chunk > s.budget {
				chunk = s.budget
			}
			n, err := s.w.Write(p[off : off+int(chunk)])
			s.written += int64(n)
			s.budget -= int64(n)
			off += n
			if err != nil {
				return off, err
			}
			continue
		}
		// Smooth phase: pass through, arm the first segment when bulk.
		n, err := s.w.Write(p[off:])
		s.written += int64(n)
		off += n
		if s.written >= s.params.threshold {
			s.budget = s.nextBudget()
		}
		if err != nil {
			return off, err
		}
	}
	return total, nil
}
