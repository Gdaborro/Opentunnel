package panel

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoIP wraps an offline MaxMind mmdb for country resolution (no runtime
// network lookups; the DB file ships on the server, not in the binary).
type GeoIP struct {
	r *geoip2.Reader
}

// OpenGeoIP opens a GeoLite2/GeoIP2 mmdb file. Returns nil on error so the
// panel degrades gracefully (countries simply stay empty).
func OpenGeoIP(path string) *GeoIP {
	if path == "" {
		return nil
	}
	r, err := geoip2.Open(path)
	if err != nil {
		return nil
	}
	return &GeoIP{r: r}
}

// Close releases the mmdb handle.
func (g *GeoIP) Close() error {
	if g == nil || g.r == nil {
		return nil
	}
	return g.r.Close()
}

// CountryName resolves an IP to an English country name ("" when unknown).
func (g *GeoIP) CountryName(ip string) string {
	if g == nil || g.r == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	rec, err := g.r.Country(parsed)
	if err != nil {
		return ""
	}
	return rec.Country.Names["en"]
}

// CountryISO resolves an IP to an ISO country code ("" when unknown).
func (g *GeoIP) CountryISO(ip string) string {
	if g == nil || g.r == nil {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	rec, err := g.r.Country(parsed)
	if err != nil {
		return ""
	}
	return rec.Country.IsoCode
}
