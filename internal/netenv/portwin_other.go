//go:build !windows

package netenv

import "net"

// PortHeldByOtu is Windows-only; elsewhere we report the raw conflict.
func PortHeldByOtu(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}
