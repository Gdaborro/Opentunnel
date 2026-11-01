package server

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseTLSError: stdlib TLS handshake error lines classify into scanner
// intel; unrelated lines are ignored.
func TestParseTLSError(t *testing.T) {
	cases := []struct {
		line  string
		ip    string
		class string
		ok    bool
	}{
		{"http: TLS handshake error from 4.148.240.217:56712: tls: client offered only unsupported versions: [301]",
			"4.148.240.217", "old-tls", true},
		{"http: TLS handshake error from [2001:db8::1]:443: tls: first record does not look like a TLS handshake",
			"2001:db8::1", "not-tls", true},
		{"http: TLS handshake error from 198.51.100.3:50123: client sent an HTTP request to an HTTPS server",
			"198.51.100.3", "http-on-tls", true},
		{"http: TLS handshake error from 203.0.113.8:1000: tls: no cipher suite supported by both client and server",
			"203.0.113.8", "cipher", true},
		{"http: TLS handshake error from 203.0.113.9:1000: EOF",
			"203.0.113.9", "eof", true},
		{"http: TLS handshake error from 203.0.113.10:1000: some future error", "203.0.113.10", "other", true},
		{"server: handshake rejected: bad salt", "", "", false},
		{"http: TLS handshake error from nonsense: no port", "", "", false},
	}
	for _, c := range cases {
		ip, class, ok := parseTLSError(c.line)
		if ok != c.ok || ip != c.ip || class != c.class {
			t.Errorf("parseTLSError(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.line, ip, class, ok, c.ip, c.class, c.ok)
		}
	}
}

// TestSentinelLogWriter: every line is forwarded verbatim (journal parity)
// and TLS errors additionally feed the sentinel.
func TestSentinelLogWriter(t *testing.T) {
	var buf bytes.Buffer
	st := newSentinelStub()
	s := NewSentinel(st, nil)
	w := SentinelLogWriter(s, &buf)

	lines := []string{
		"http: TLS handshake error from 203.0.113.50:1234: tls: first record does not look like a TLS handshake\n",
		"alt listener: something benign\n",
	}
	for _, l := range lines {
		if _, err := w.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	out := buf.String()
	for _, want := range []string{"203.0.113.50", "alt listener: something benign"} {
		if !strings.Contains(out, want) {
			t.Fatalf("forwarded log missing %q:\n%s", want, out)
		}
	}

	// The sink counted the TLS error: flood it and watch the probe alert.
	for i := 0; i < sentinelProbeFlood; i++ {
		w.Write([]byte("http: TLS handshake error from 203.0.113.50:1234: client sent an HTTP request to an HTTPS server\n"))
	}
	if !strings.Contains(st.alertText(), "scanning from 203.0.113.50") {
		t.Fatalf("writer must feed sentinel probes, alerts: %q", st.alertText())
	}
}
