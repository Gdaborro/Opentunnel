package transport

import (
	"testing"

	"opentunnel/internal/protocol"
)

// TestBoringWSPath pins the boring endpoint default: "/ws" plus a custom
// subprotocol announced the tunnel by name under interception.
func TestBoringWSPath(t *testing.T) {
	if DefaultWSPath != protocol.DefaultWSPath {
		t.Fatal("transport default must track protocol.DefaultWSPath")
	}
	if DefaultWSPath == "/ws" || DefaultWSPath == "" || DefaultWSPath[0] != '/' {
		t.Fatalf("default path must be boring and absolute, got %q", DefaultWSPath)
	}
	if protocol.LegacyWSPath != "/ws" {
		t.Fatalf("legacy path must stay /ws, got %q", protocol.LegacyWSPath)
	}
	var opt WSTLSOptions
	if opt.wsPathOrDefault() != protocol.DefaultWSPath {
		t.Fatal("empty WSPath must resolve to the boring default")
	}
	opt.WSPath = "/custom"
	if opt.wsPathOrDefault() != "/custom" {
		t.Fatal("explicit WSPath must win")
	}
}
