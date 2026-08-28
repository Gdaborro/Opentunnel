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
