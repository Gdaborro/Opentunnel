package server

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// restrictedPrefixes are non-routable or provider-internal ranges a
// tunneled target must never reach. Kept next to the netip predicates so
// the whole policy reads in one place (1.0.1 hardening: the old net.IP
// implementation failed OPEN on anything net.ParseIP could not parse —
// e.g. `::1%lo` zone literals walked straight into the loopback admin
// plane, and NAT64 literals mapped around the v4 checks).
var restrictedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT (cloud provider internals)
	netip.MustParsePrefix("169.254.0.0/16"), // link-local incl. 169.254.169.254 metadata
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64: reaches arbitrary v4 via a v6 literal
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
}

// restrictedAddr reports whether a (zone-stripped, unmapped) address is in
// a sensitive range.
func restrictedAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range restrictedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// isRestrictedIP reports whether dialing ip would reach a sensitive range.
// Fails closed: a nil or unparseable value is restricted.
func isRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return restrictedAddr(a)
}

// safeControl is a net.Dialer.Control hook that refuses connections into
// restricted ranges. It runs after DNS resolution, so domains that resolve
// to internal addresses (DNS-rebinding style) are rejected too.
//
// Fails CLOSED (1.0.1): the previous implementation returned nil for
// anything net.ParseIP could not parse, so a target like `[::1%lo]:80`
// (zone identifiers make ParseIP return nil) reached the loopback admin
// plane and internal listeners. Zone identifiers are now stripped for the
// range check — a zone never makes a restricted address safe — and
// unparseable hosts are refused outright.
func safeControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("server: target %q is malformed", address)
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		// Post-resolution the host must be an IP; anything else is a
		// protocol violation or an evasion attempt.
		return fmt.Errorf("server: target %q is not a valid address", address)
	}
	if restrictedAddr(a) {
		return fmt.Errorf("server: target %s is in a restricted range", host)
	}
	return nil
}
