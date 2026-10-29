package proxy

import (
	"errors"
	"strings"
	"testing"

	"opentunnel/internal/protocol"
)

// TestKillSwitchDownPage: the kill-switch block page must present the
// admin's reason with the "traffic down" framing and no domain-blame.
// Errors arrive at the proxy as strings ("down: <reason>" — the shape
// client.BlockedError.Error() produces for kind "down").
func TestKillSwitchDownPage(t *testing.T) {
	addr, err := protocol.ParseAddress("example.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	downErr := errors.New("down: shut down till further notice")
	html := serveBlockPageHTML(addr, downErr)
	if !strings.Contains(html, "Traffic temporarily down") {
		t.Fatal("down page title missing")
	}
	if !strings.Contains(html, "shut down till further notice") {
		t.Fatal("admin reason missing from the page")
	}
	if strings.Contains(html, "example.org") {
		t.Fatal("down page must not blame the requested domain")
	}
	if !isBlockedErr(downErr) {
		t.Fatal("down errors must route to the block-page path")
	}
	if got := blockReason(downErr); got != "shut down till further notice" {
		t.Fatalf("blockReason = %q", got)
	}
}
