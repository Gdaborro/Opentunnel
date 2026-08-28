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

// SshTierName is the virtual last-resort tier riding inside real SSH.
const SshTierName = "ssh"

// tierCount returns how many tiers exist including the optional SSH fallback.
func (a *Adaptive) tierCount() int {
	if a.sshFallback != nil {
		return len(profileOrder) + 1
	}
	return len(profileOrder)
}

// tierName maps a tier index to a display/build name.
func (a *Adaptive) tierName(idx int) string {
	if idx < len(profileOrder) {
		return profileOrder[idx]
	}
	return SshTierName
}

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
	failStreak  int         // consecutive failures on current tier

	// transportBuilder lets configs swap the underlying transport per
	// profile (e.g. ssh). Defaults to ws-tls with Chrome hello above fast.
	transportBuilder func(profile string) transport.Transport

	// sshFallback, when set, adds a final last-resort tier that tunnels
	// inside real SSH — used when every ws-tls tier is intercepted.
	sshFallback func() transport.Transport

	// OnAuthRejected is forwarded to every built client: it fires when the
	// panel no longer knows the device token (purged/expired) so the device
	// can re-register and re-enter the approval queue.
	OnAuthRejected func()
}

// EnableMux turns on connection multiplexing for every profile's clients.
func (a *Adaptive) EnableMux() { a.mux = true }

// EnableSSHFallback adds the ssh last-resort tier to the ladder.
func (a *Adaptive) EnableSSHFallback(builder func() transport.Transport) {
	a.sshFallback = builder
}

// UseTransportBuilder overrides how per-profile transports are constructed.
func (a *Adaptive) UseTransportBuilder(f func(profile string) transport.Transport) {
	a.transportBuilder = f
}

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
	name := a.tierName(idx)
	var tr transport.Transport
	if idx >= len(profileOrder) && a.sshFallback != nil {
		tr = a.sshFallback()
	} else if a.transportBuilder != nil {
		tr = a.transportBuilder(name)
	} else {
		opt := a.base
		opt.ChromeHello = name != ProfileFast
		tr = transport.NewWSTLS(opt)
	}
	return NewWithOptions(tr, Options{
		Token:          a.token,
		DialTimeout:    a.dialTimeout,
		Profile:        "balanced", // under ssh, mild padding; harmless elsewhere
		Mux:            a.mux,
		OnAuthRejected: a.OnAuthRejected,
	})
}

func (a *Adaptive) build(idx int) *Client { return a.factory(a, idx) }

// fatalUpstream reports errors that indicate the tunnel works but the target
// is unreachable — escalating profiles cannot help. Pending/expired device
// tokens and ISP blocks are also terminal: no transport tier can fix them.
func fatalUpstream(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pend *PendingError
	if errors.As(err, &pend) {
		return true
	}
	var be *BlockedError
	if errors.As(err, &be) {
		return true
	}
	var pe *protocol.StatusError
	return errors.As(err, &pe) && pe.Status == protocol.StatusDialFailed
}

// DialTunnel implements proxy.Dialer with adaptive tier selection.
func (a *Adaptive) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	a.mu.Lock()
	start := a.idx
	probeDown := a.auto && start > 0 && time.Since(a.lastProbe) > 10*time.Minute
	// Probe downward early if the current tier keeps failing (e.g. the
	// fallback tier itself became unreachable) instead of waiting out the
	// full cool-off.
	if a.failStreak >= 3 {
		a.lastProbe = time.Now()
		a.failStreak = 0
		probeDown = start > 0
	}
	if probeDown {
		a.lastProbe = time.Now()
	}
	total := a.tierCount()
	a.mu.Unlock()

	order := []int{}
	if probeDown {
		order = append(order, 0)
	}
	for i := start; i < total; i++ {
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
			a.failStreak = 0
			switch {
			case probeDown && idx == 0:
				a.idx = 0 // lower profile healthy again — stay fast
				a.logger().Printf("adaptive: fast profile healthy again — back to %q", ProfileFast)
			default:
				if idx > a.idx {
					a.idx = idx // escalated this call: stick here
					a.logger().Printf("adaptive: escalated to %q", a.tierName(idx))
					// Re-probe lower tiers only after a cool-off.
					a.lastProbe = time.Now()
				}
				// Slow-but-successful hints at active throttling of the
				// current tier: pre-escalate for subsequent dials.
				if a.auto && idx == a.idx && elapsed > a.ttfbBudget && a.idx+1 < total {
					a.idx++
					a.lastProbe = time.Now()
					a.logger().Printf("adaptive: slow response (%s) — pre-escalating to %q", elapsed.Round(time.Millisecond), a.tierName(a.idx))
				}
			}
			a.mu.Unlock()
			return conn, nil
		}
		if fatalUpstream(err) {
			return nil, err
		}
		a.mu.Lock()
		lastErr = fmt.Errorf("tier %q: %w", a.tierName(idx), err)
		if idx == a.idx {
			a.failStreak++
		}
		a.mu.Unlock()
	}
	if lastErr == nil {
		lastErr = errors.New("client: no tiers available")
	}
	return nil, lastErr
}

// Current reports the active tier name (for status output).
func (a *Adaptive) Current() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tierName(a.idx)
}

// Probe measures tunnel setup latency on the current tier (transport dial +
// handshake), then tears the connection down. Used for health telemetry.
func (a *Adaptive) Probe(ctx context.Context) (time.Duration, error) {
	a.mu.Lock()
	idx := a.idx
	a.mu.Unlock()
	return a.build(idx).ProbeSession(ctx)
}

// OpenUDPRelay returns a UDP relay stream using the currently selected
// profile. It implements proxy.UDPDialer.
func (a *Adaptive) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	a.mu.Lock()
	idx := a.idx
	a.mu.Unlock()
	return a.build(idx).OpenUDPRelay(ctx)
}
