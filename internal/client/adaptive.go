package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

// Profile names, in escalation order: each step adds obfuscation overhead
// only when the previous one appears blocked or throttled.
const (
	ProfileFast     = "fast"     // plain TLS+WS, no shaping — fastest
	ProfileBalanced = "balanced" // Chrome-fingerprint hello + size-bucket padding
	ProfileStealth  = "stealth"  // balanced + per-frame write jitter
)

var profileOrder = []string{ProfileFast, ProfileBalanced, ProfileStealth}

// ParseProfile validates a configured profile name ("auto" handled by NewAdaptive).
func ValidProfile(name string) bool {
	switch name {
	case "auto", ProfileFast, ProfileBalanced, ProfileStealth:
		return true
	}
	return false
}

// Adaptive picks profiles automatically. It starts at Fast, escalates when a
// profile fails or responds slower than TTFBBudget, and periodically re-probes
// lower profiles so users drop back to maximum speed whenever possible.
type Adaptive struct {
	mu          sync.Mutex
	token       string
	base        transport.WSTLSOptions
	idx         int // index into profileOrder
	auto        bool
	lastProbe   time.Time
	ttfbBudget  time.Duration
	dialTimeout time.Duration
	factory     func(a *Adaptive, idx int) *Client
	Logger      *log.Logger // optional; nil = log.Default()
	mux         bool        // multiplexing requested by config
}

// EnableMux turns on connection multiplexing for every profile's clients.
func (a *Adaptive) EnableMux() { a.mux = true }

func (a *Adaptive) logger() *log.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return log.Default()
}

func NewAdaptive(token string, base transport.WSTLSOptions, profile string, dialTimeout time.Duration) *Adaptive {
	a := &Adaptive{
		token:       token,
		base:        base,
		auto:        profile == "auto",
		ttfbBudget:  3 * time.Second,
		dialTimeout: dialTimeout,
	}
	a.factory = defaultFactory
	if !a.auto {
		for i, p := range profileOrder {
			if p == profile {
				a.idx = i
				break
			}
		}
	}
	return a
}

func defaultFactory(a *Adaptive, idx int) *Client {
	name := profileOrder[idx]
	opt := a.base
	opt.ChromeHello = name != ProfileFast
	tr := transport.NewWSTLS(opt)
	return NewWithOptions(tr, Options{
		Token:       a.token,
		DialTimeout: a.dialTimeout,
		Profile:     name,
		Mux:         a.mux,
	})
}

func (a *Adaptive) build(idx int) *Client { return a.factory(a, idx) }

// fatalUpstream reports errors that indicate the tunnel works but the target
// is unreachable — escalating profiles cannot help.
func fatalUpstream(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pe *protocol.StatusError
	return errors.As(err, &pe) && pe.Status == protocol.StatusDialFailed
}

// DialTunnel implements proxy.Dialer with adaptive profile selection.
func (a *Adaptive) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	a.mu.Lock()
	start := a.idx
	probeDown := a.auto && start > 0 && time.Since(a.lastProbe) > 10*time.Minute
	if probeDown {
		a.lastProbe = time.Now()
	}
	a.mu.Unlock()

	order := []int{}
	if probeDown {
		order = append(order, 0)
	}
	for i := start; i < len(profileOrder); i++ {
		if probeDown && i == 0 {
			continue
		}
		order = append(order, i)
	}

	var lastErr error
	for _, idx := range order {
		cl := a.build(idx)
		t0 := time.Now()
		conn, err := cl.DialTunnel(ctx, target)
		if err == nil {
			elapsed := time.Since(t0)
			a.mu.Lock()
			switch {
			case probeDown && idx == 0:
				a.idx = 0 // lower profile healthy again — stay fast
				a.logger().Printf("adaptive: fast profile healthy again — back to %q", ProfileFast)
			default:
				if idx > a.idx {
					a.idx = idx // escalated this call: stick here
					a.logger().Printf("adaptive: escalated to %q", profileOrder[idx])
					// Re-probe lower tiers only after a cool-off.
					a.lastProbe = time.Now()
				}
				// Slow-but-successful hints at active throttling of the
				// current tier: pre-escalate for subsequent dials.
				if a.auto && idx == a.idx && elapsed > a.ttfbBudget && a.idx+1 < len(profileOrder) {
					a.idx++
					a.lastProbe = time.Now()
					a.logger().Printf("adaptive: slow response (%s) — pre-escalating to %q", elapsed.Round(time.Millisecond), profileOrder[a.idx])
				}
			}
			a.mu.Unlock()
			return conn, nil
		}
		if fatalUpstream(err) {
			return nil, err
		}
		lastErr = fmt.Errorf("profile %q: %w", profileOrder[idx], err)
	}
	if lastErr == nil {
		lastErr = errors.New("client: no profiles available")
	}
	return nil, lastErr
}

// Current reports the active profile name (for status output).
func (a *Adaptive) Current() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return profileOrder[a.idx]
}

// OpenUDPRelay returns a UDP relay stream using the currently selected
// profile. It implements proxy.UDPDialer.
func (a *Adaptive) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	a.mu.Lock()
	idx := a.idx
	a.mu.Unlock()
	return a.build(idx).OpenUDPRelay(ctx)
}
