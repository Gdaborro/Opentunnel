package proxy

import (
	"context"
	"errors"
	"net"
	"sync"

	"opentunnel/internal/protocol"
)

// BanGate is a client-side switch that turns every new proxied connection
// into a ban notice. The gate feeds the existing block-page machinery: the
// dial error carries the "banned:" prefix, so plain-HTTP pages, HTTP proxy
// CONNECT replies and SOCKS port-80 replies all render the Banned variant
// of the block page with the administrator's reason.
type BanGate struct {
	mu     sync.RWMutex
	active bool
	reason string
}

// Activate turns the gate on: from now on every dial fails with the ban
// notice error. An empty reason yields a generic message.
func (g *BanGate) Activate(reason string) {
	g.mu.Lock()
	g.active = true
	g.reason = reason
	g.mu.Unlock()
}

// Deactivate turns the gate off (e.g. the ban was lifted mid-grace):
// dials flow to the tunnel again.
func (g *BanGate) Deactivate() {
	g.mu.Lock()
	g.active = false
	g.reason = ""
	g.mu.Unlock()
}

// Active reports whether the gate is on.
func (g *BanGate) Active() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.active
}

// Reason returns the ban reason given at activation.
func (g *BanGate) Reason() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.reason
}

// Err builds the dial error the proxy handlers translate into the ban
// page (nil when the gate is off).
func (g *BanGate) Err() error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.active {
		return nil
	}
	if g.reason == "" {
		return errors.New("banned")
	}
	return errors.New("banned: " + g.reason)
}

// BanDialer wraps a tunnel Dialer with a BanGate. While the gate is off it
// forwards everything (tunnel + UDP relay); once activated, every dial
// fails with the ban notice so each webpage displays it.
type BanDialer struct {
	Inner Dialer
	Gate  *BanGate
}

// DialTunnel implements Dialer.
func (d *BanDialer) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	if d.Gate != nil {
		if err := d.Gate.Err(); err != nil {
			return nil, err
		}
	}
	if d.Inner == nil {
		return nil, errors.New("banned")
	}
	return d.Inner.DialTunnel(ctx, target)
}

// OpenUDPRelay implements UDPDialer by forwarding (gated shut when active).
func (d *BanDialer) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	if d.Gate != nil {
		if err := d.Gate.Err(); err != nil {
			return nil, err
		}
	}
	ud, ok := d.Inner.(UDPDialer)
	if !ok || d.Inner == nil {
		return nil, errors.New("udp relay unavailable")
	}
	return ud.OpenUDPRelay(ctx)
}
