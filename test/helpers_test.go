package test

import (
	"fmt"
	"strconv"
	"strings"

	"opentunnel/internal/protocol"
)

// parseAddrForTest builds a protocol.Address from host/port strings.
func parseAddrForTest(host, port string) (*protocol.Address, error) {
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return nil, fmt.Errorf("bad port %q: %w", port, err)
	}
	return protocol.ParseAddress(host, p)
}
