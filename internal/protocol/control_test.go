package protocol

import (
	"net"
	"testing"
)

// TestCtrlMessageRoundTrip pins the [u16 length][JSON] control framing in
// both directions.
func TestCtrlMessageRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		req := CtrlRequest{Op: "health", Token: "tok", Version: "v0.9.23", CPUPct: 12.5}
		if err := WriteCtrlMessage(c1, req); err != nil {
			t.Errorf("write: %v", err)
		}
		var resp CtrlResponse
		if err := WriteCtrlMessage(c1, resp); err != nil {
			t.Errorf("write resp: %v", err)
		}
	}()

	var got CtrlRequest
	if err := ReadCtrlMessage(c2, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Op != "health" || got.Token != "tok" || got.Version != "v0.9.23" || got.CPUPct != 12.5 {
		t.Fatalf("request round trip = %+v", got)
	}
	var resp CtrlResponse
	if err := ReadCtrlMessage(c2, &resp); err != nil {
		t.Fatalf("read resp: %v", err)
	}
	if resp.OK || resp.Pin != "" {
		t.Fatalf("zero response must decode empty, got %+v", resp)
	}
}
