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
)

// Transport connects to an opentunnel server and yields a raw byte stream
// on which the protocol handshake is then performed by the caller.
type Transport interface {
	Name() string
	Dial(ctx context.Context) (net.Conn, error)
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
