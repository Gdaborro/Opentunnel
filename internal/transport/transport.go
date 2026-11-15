// Package transport defines the pluggable-transport interface and provides
// concrete transports. A Transport produces one authenticated-tunnel-ready
// stream connection per Dial.
package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Transport connects to an opentunnel server and yields a raw byte stream
// on which the protocol handshake is then performed by the caller.
type Transport interface {
	Name() string
	Dial(ctx context.Context) (net.Conn, error)
}

// SetupDialer separates a bounded establishment deadline from the lifetime of
// the established stream. Canceling setup after success must not close it.
type SetupDialer interface {
	DialSetup(setup, lifetime context.Context) (net.Conn, error)
}

// AbortSetup tears down a failed, unadopted connection without a graceful
// close-handshake wait extending its establishment budget. Live connections
// still use their ordinary graceful Close behavior.
func AbortSetup(conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Now())
	if immediate, ok := conn.(interface{ CloseNow() error }); ok {
		_ = immediate.CloseNow()
		return
	}
	_ = conn.Close()
}

// ParseFingerprint validates and normalizes a hex-encoded SHA-256 certificate
// pin ("aa:bb:.." or "aabb..").
func ParseFingerprint(fp string) ([]byte, error) {
	clean := strings.NewReplacer(":", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(fp)))
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("transport: bad fingerprint encoding: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("transport: fingerprint must be %d bytes, got %d", sha256.Size, len(raw))
	}
	return raw, nil
}

// FingerprintCert returns the SHA-256 digest of a DER certificate.
func FingerprintCert(der []byte) []byte {
	sum := sha256.Sum256(der)
	return sum[:]
}
