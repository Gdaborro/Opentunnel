// cfip.go: real-client resolution behind an optional Cloudflare front.
// CDN-fronted relays see only CF edge IPs on the TCP socket; per-IP guards,
// GeoIP and rate limits need the real client. The CF-Connecting-IP header
// is honored ONLY when the TCP peer is a published Cloudflare range — a
// spoofed header from any other source is ignored.
package server

import (
	"net"
	"net/http"
)

// cloudflareCIDRs: Cloudflare's published edge ranges (IPv4 + IPv6).
// Update when https://www.cloudflare.com/ips changes (rare).
var cloudflareCIDRs = mustParseCIDRs([]string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"240f:f800::/32",
	"2405:b500::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("server: bad cloudflare range " + c)
		}
		out = append(out, n)
	}
	return out
}

// IsCloudflareIP reports whether ip belongs to a Cloudflare edge range.
func IsCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range cloudflareCIDRs {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ResolveClientIP returns the real client IP for a request: the
// CF-Connecting-IP header when the peer is a trusted Cloudflare edge
// (spoofed headers from anyone else are ignored), else the TCP peer
// itself. When trustCF is false the header is never consulted.
func ResolveClientIP(r *http.Request, trustCF bool) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if !trustCF || !IsCloudflareIP(peer) {
		return peer
	}
	if cip := net.ParseIP(r.Header.Get("CF-Connecting-IP")); cip != nil {
		return cip.String()
	}
	return peer
}
