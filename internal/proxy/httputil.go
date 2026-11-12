package proxy

import (
	"context"
	"net"
	"strconv"

	"opentunnel/internal/protocol"
	"opentunnel/internal/streamio"
)

func authorityToAddr(authority string) (*protocol.Address, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		// CONNECT normally includes an explicit port. Accept a bare host
		// only when it is not a malformed IPv6/host:port authority.
		if net.ParseIP(authority) == nil {
			for _, c := range authority {
				if c == ':' || c == '/' || c == '@' {
					return nil, err
				}
			}
		}
		host, port = authority, "443"
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	return protocol.ParseAddress(host, p)
}

// Pipe preserves TCP/smux half-close semantics and joins all copy workers on
// completion or cancellation. Long healthy transfers have no fixed deadline.
func Pipe(ctx context.Context, a, b net.Conn) { _, _, _ = streamio.Pipe(ctx, a, b) }
