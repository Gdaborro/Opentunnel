package server

import (
	"fmt"
	"net"
	"syscall"
)

// isRestrictedIP reports whether dialing ip would reach a sensitive range:
// loopback, RFC1918/ULA private, link-local (includes the 169.254.169.254
// cloud metadata endpoint), CGNAT (100.64.0.0/10, used by cloud provider
// internals), multicast, or unspecified addresses.
func isRestrictedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1]&0xC0 == 64 {
		return true // 100.64.0.0/10 CGNAT
	}
	return false
}

// safeControl is a net.Dialer.Control hook that refuses connections into
// restricted ranges. It runs after DNS resolution, so domains that resolve
// to internal addresses (DNS-rebinding style) are rejected too.
func safeControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if isRestrictedIP(ip) {
		return fmt.Errorf("server: target %s is in a restricted range", host)
	}
	return nil
}
