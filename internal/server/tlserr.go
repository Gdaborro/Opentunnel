package server

// tlserr.go — scanner intel from the HTTP server's error log (v1.1.0).
//
// Every "http: TLS handshake error" line is a peer that failed before HTTP
// even started: obsolete TLS versions, plain HTTP sent at the TLS port,
// junk bytes, cipher mismatches. The real fleet connects over TLS 1.2/1.3
// with no such errors, so a flood is meaningful scanner traffic. The
// writer forwards every line to the console unchanged (journal parity) and
// additionally feeds classified errors into the sentinel.

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// SentinelLogWriter wraps an http.Server ErrorLog sink: it forwards lines
// to base and reports TLS handshake errors to s as probe events.
func SentinelLogWriter(s *Sentinel, base io.Writer) io.Writer {
	if base == nil {
		base = io.Discard
	}
	return &sentinelLogWriter{s: s, base: base}
}

type sentinelLogWriter struct {
	s    *Sentinel
	base io.Writer
}

func (w *sentinelLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if w.s != nil {
		if ip, class, ok := parseTLSError(line); ok {
			w.s.Probe(ip, "tls/"+class)
		}
	}
	fmt.Fprintf(w.base, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), line)
	return len(p), nil
}

// parseTLSError extracts (ip, class) from a Go stdlib TLS handshake error
// line: "http: TLS handshake error from 1.2.3.4:5678: <reason>".
func parseTLSError(line string) (ip, class string, ok bool) {
	const prefix = "http: TLS handshake error from "
	if !strings.HasPrefix(line, prefix) {
		return "", "", false
	}
	rest := line[len(prefix):]
	i := strings.Index(rest, ": ")
	if i <= 0 {
		return "", "", false
	}
	hostport := rest[:i]
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if net.ParseIP(host) == nil {
		return "", "", false
	}
	msg := rest[i:]
	class = "other"
	switch {
	case strings.Contains(msg, "does not look like a TLS handshake"):
		class = "not-tls"
	case strings.Contains(msg, "HTTP request to an HTTPS server"):
		class = "http-on-tls"
	case strings.Contains(msg, "unsupported versions") || strings.Contains(msg, "no supported versions"):
		class = "old-tls"
	case strings.Contains(msg, "no cipher suite"):
		class = "cipher"
	case strings.Contains(msg, "unexpected EOF"), strings.Contains(msg, "EOF"):
		class = "eof"
	}
	return host, class, true
}
