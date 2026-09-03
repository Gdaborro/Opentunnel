//go:build windows

package netenv

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// PortHeldByOtu reports whether the TCP port at addr (host:port) is currently
// held by an otu-client process. Used for friendly single-instance behavior
// instead of crashing into a port conflict.
func PortHeldByOtu(addr string) bool {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	out, err := exec.Command("netstat", "-ano", "-p", "TCP").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		// LISTEN rows: proto local foreign state pid
		if len(f) == 5 && strings.EqualFold(f[3], "LISTENING") && strings.HasSuffix(f[1], ":"+portStr) {
			if pid, perr := strconv.Atoi(f[4]); perr == nil && isOtuProcess(uint32(pid)) {
				return true
			}
		}
	}
	return false
}
