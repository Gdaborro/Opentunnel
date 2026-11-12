package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// LoopbackEndpoint rejects DNS aliases, wildcard binds and scoped literals.
// This trust boundary must not depend on DNS or a mutable hosts file.
func LoopbackEndpoint(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid loopback endpoint: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() {
		return fmt.Errorf("endpoint must use a literal loopback IP")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("endpoint port must be 1..65535")
	}
	return nil
}
