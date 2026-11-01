package server

import (
	"net"
	"testing"
)

func TestIsRestrictedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5", true},
		{"172.16.3.4", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"100.64.0.1", true},      // CGNAT
		{"100.127.255.254", true}, // CGNAT upper bound
		{"fc00::1", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"224.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"100.128.0.1", false}, // just outside CGNAT
		{"9.255.255.255", false},
		{"2001:4860:4860::8888", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test ip %q", c.ip)
		}
		if got := isRestrictedIP(ip); got != c.want {
			t.Errorf("isRestrictedIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// TestRestrictedAddrHardening (1.0.1): mapped, NAT64 and reserved ranges
// are all restricted; isRestrictedIP fails closed on nil.
func TestRestrictedAddrHardening(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"::ffff:127.0.0.1", true}, // v4-mapped loopback
		{"64:ff9b::7f00:1", true},  // NAT64 of 127.0.0.1
		{"240.0.0.1", true},        // reserved
		{"198.18.0.1", true},       // benchmarking
		{"192.0.0.8", true},        // IETF protocol assignments
		{"9.9.9.9", false},
	}
	for _, c := range cases {
		if got := isRestrictedIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isRestrictedIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
	if !isRestrictedIP(nil) {
		t.Error("isRestrictedIP(nil) must fail closed")
	}
}

// TestSafeControlFailsClosed (1.0.1): the SSRF hook must refuse zone
// identifiers, NAT64 literals and unparseable hosts instead of failing
// open.
func TestSafeControlFailsClosed(t *testing.T) {
	cases := []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:80", true},
		{"[::1]:80", true},
		{"[::1%lo]:80", true},
		{"[fe80::1%eth0]:22", true},
		{"[64:ff9b::7f00:1]:80", true},
		{"[64:ff9b::808:808]:443", true},
		{"8.8.8.8:443", false},
		{"[2001:4860:4860::8888]:443", false},
		{"garbage", true},
		{"[not-an-ip]:80", true},
	}
	for _, c := range cases {
		err := safeControl("tcp", c.addr, nil)
		if (err != nil) != c.wantErr {
			t.Errorf("safeControl(%q) err=%v, wantErr=%v", c.addr, err, c.wantErr)
		}
	}
}
