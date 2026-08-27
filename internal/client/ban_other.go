//go:build !windows

package client

import (
	"crypto/sha256"
	"fmt"
	"os"
)

func deviceFingerprint() string {
	hostname, _ := os.Hostname()
	raw := fmt.Sprintf("other|%s", hostname)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:16])
}

func isRegistryBanned() bool { return false }
func writeRegistryBan(reason, duration string) {}
