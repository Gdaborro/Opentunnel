package client

import (
	"strings"
	"testing"

	"opentunnel/internal/transport"
)

// TestProbeRequestMatchesBrowserStory pins the throughput probe's request
// shape: the User-Agent must match the tunnel's Chrome hello (the old
// Chrome/126 string contradicted the Chrome/133 parrot on the same flow),
// and the fetch must look like an ordinary resumable download (Range).
func TestProbeRequestMatchesBrowserStory(t *testing.T) {
	req := probeRequest("/files/100Mb.dat", "proof.ovh.net", 2<<20)
	if !strings.Contains(req, "GET /files/100Mb.dat HTTP/1.1\r\n") {
		t.Errorf("malformed request line in:\n%s", req)
	}
	if !strings.Contains(req, "Host: proof.ovh.net\r\n") {
		t.Errorf("missing Host in:\n%s", req)
	}
	if !strings.Contains(req, "Range: bytes=0-2097151\r\n") {
		t.Errorf("missing Range header in:\n%s", req)
	}
	if !strings.Contains(req, "User-Agent: "+transport.BrowserUA+"\r\n") {
		t.Errorf("User-Agent must match the tunnel's Chrome story:\n%s", req)
	}
	if strings.Contains(req, "Chrome/126") {
		t.Error("stale Chrome/126 string leaked into the probe request")
	}
}
