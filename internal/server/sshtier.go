// sshtier.go: ssh-tier containment. The ssh transport is the only tier
// that survives networks which both intercept TLS (pinning never passes)
// and drop UDP (h3 never passes) — school/enterprise networks. That makes
// it the tier where a fleet's traffic is most conspicuous: many devices
// fanning into one relay IP over port 22, each pushing media-sized daily
// volume reads as a video feed on the wire, not as ordinary SSH usage
// (git fetches are bursty and modest).
//
// Containment has two knobs, both operator-set in panel settings:
//
//   - a sustained per-device bandwidth ceiling for ssh ingress, so a
//     single flow can never look like a line-rate media stream;
//   - a per-device daily byte budget for ssh ingress. Once spent, new
//     ssh streams degrade to a trickle rate (~200 kbps by default):
//     interactive browsing stays usable, media streaming cannot hold,
//     and the flow shape stays ordinary.
//
// The budget counter is process-local (the relay's memory): a restart
// resets it, and enforcement applies per stream at relayTarget/serveUDPStream
// start. Both are deliberate — the goal is flow-shape containment, not
// billing-grade accounting, and existing streams age out through the
// normal mux rotation (25 min, jittered).
package server

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// IngressSSH marks requests that arrived through the internal loopback
// listener — the ssh transport's forward path (sshd permitopen ->
// listen_internal). Public TLS and h3 arrivals carry no marker.
const IngressSSH = "ssh"

type ingressKey struct{}

// WithIngress wraps next so every request it serves carries the given
// ingress marker (see ingressFrom). Used to mount the loopback listener
// with IngressSSH while the public listeners stay unmarked.
func WithIngress(next http.Handler, ingress string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ingressKey{}, ingress)))
	})
}

// ingressFrom reads the marker WithIngress installed ("" = public).
func ingressFrom(r *http.Request) string {
	v, _ := r.Context().Value(ingressKey{}).(string)
	return v
}

// sshTierBudget tracks per-device daily ssh-ingress bytes. Day boundaries
// are UTC; the first call of a new day drops the previous day's counters.
type sshTierBudget struct {
	mu   sync.Mutex
	day  string
	used map[string]int64
}

var sshBudgetV = &sshTierBudget{}

func sshBudgetDay(now time.Time) string { return now.UTC().Format("2006-01-02") }

// rollLocked resets the map when the UTC day changed (caller holds mu).
func (b *sshTierBudget) rollLocked(now time.Time) {
	d := sshBudgetDay(now)
	if b.day == d {
		return
	}
	b.day = d
	b.used = map[string]int64{}
}

// usedAt reports token's ssh-ingress usage for the current UTC day.
func (b *sshTierBudget) usedAt(now time.Time, token string) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollLocked(now)
	return b.used[token]
}

// addAt records n ssh-ingress bytes for token and returns the new total.
func (b *sshTierBudget) addAt(now time.Time, token string, n int64) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollLocked(now)
	if n > 0 {
		b.used[token] += n
	}
	return b.used[token]
}

// sshBudgetUsed / sshBudgetAdd are the wall-clock wrappers.
func sshBudgetUsed(token string) int64         { return sshBudgetV.usedAt(time.Now(), token) }
func sshBudgetAdd(token string, n int64) int64 { return sshBudgetV.addAt(time.Now(), token, n) }

// streamPolicy is the resolved containment decision for one stream.
type streamPolicy struct {
	// limitBps caps the stream's pacing in bytes/sec (0 = unlimited).
	limitBps int64
	// budgetBytes, when > 0, is the device's daily ssh-ingress budget
	// that this stream's bytes count against.
	budgetBytes int64
}

// defaultPostBudgetBps is the trickle rate used when a device's daily ssh
// budget is spent and no explicit post-budget rate is configured:
// 25 KB/s ≈ 200 kbps — pages still load, video cannot hold a buffer.
const defaultPostBudgetBps = 25_000

// resolveStreamPolicy combines the per-device cap (applies to every
// ingress, as before) with the ssh-tier containment policy (ssh ingress
// only): a sustained ceiling plus the daily budget whose exhaustion
// degrades new streams to the trickle rate.
func resolveStreamPolicy(opt Options, token, ingress string) streamPolicy {
	if opt.PanelDB == nil || token == "" {
		return streamPolicy{}
	}
	peerMax, _ := opt.PanelDB.PeerLimits(token)
	p := streamPolicy{limitBps: peerMax}
	if ingress != IngressSSH {
		return p
	}
	sshMax, daily, trickle := opt.PanelDB.SSHTierLimits()
	p.limitBps = lowerPositive(p.limitBps, sshMax)
	if daily <= 0 {
		return p
	}
	p.budgetBytes = daily
	if sshBudgetUsed(token) >= daily {
		if trickle <= 0 {
			trickle = defaultPostBudgetBps
		}
		p.limitBps = lowerPositive(p.limitBps, trickle)
	}
	return p
}

// lowerPositive returns the stricter of two byte/sec caps, treating
// values <= 0 as "unset" (0 = unlimited).
func lowerPositive(a, b int64) int64 {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case b < a:
		return b
	}
	return a
}
