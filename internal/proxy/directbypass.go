// directbypass.go: the local proxies' loop guard. Browsers pointed at the
// system proxy will send requests for the tunnel's own entry hosts to us;
// piping those back through the relay is a loop (and used to be prevented
// by listing operator domains in the WinINET bypass list — a visible,
// self-incriminating ProxyOverride). The guard dials those hosts direct
// instead, keeping the machine's proxy settings free of operator strings.
package proxy

import (
	"context"
	"errors"
	"net"
	"strings"

	"opentunnel/internal/protocol"
)

// DirectDialer wraps a tunnel Dialer and short-circuits targets that match
// one of the configured entry hosts: they dial straight to the internet,
// never through the relay.
type DirectDialer struct {
	Inner Dialer
	// Hosts are the lowercase hostnames (no port) that dial direct —
	// typically the entry hostname, every fallback entry, and the ssh host.
	Hosts map[string]bool
}

// DialTunnel implements Dialer.
func (d *DirectDialer) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	if d.isDirect(target) {
		var zero net.Dialer
		return zero.DialContext(ctx, "tcp", target.HostPort())
	}
	return d.Inner.DialTunnel(ctx, target)
}

// OpenUDPRelay implements UDPDialer by forwarding (relay datagrams cannot
// loop: the UDP associate path never dials the entry host).
func (d *DirectDialer) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	ud, ok := d.Inner.(UDPDialer)
	if !ok || d.Inner == nil {
		return nil, errors.New("udp relay unavailable")
	}
	return ud.OpenUDPRelay(ctx)
}

// isDirect reports whether target is one of the configured entry hosts.
func (d *DirectDialer) isDirect(target *protocol.Address) bool {
	if target == nil {
		return false
	}
	host := target.Domain
	if host == "" && target.IP != nil {
		host = target.IP.String()
	}
	return d.Hosts[strings.ToLower(host)]
}
