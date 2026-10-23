package client

import (
	"context"
	"testing"

	"opentunnel/internal/config"
	"opentunnel/internal/protocol"
)

// TestCheckTokenStatusInBandFirst proves the status poll rides the
// in-band control channel when installed: no HTTPS is dialed at all
// (the pinned client would fail against this bogus config), and the
// bootstrap-only plain fallback stays off.
func TestCheckTokenStatusInBandFirst(t *testing.T) {
	SetControlChannel(func(ctx context.Context, req protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
		if req.Op != "status" || req.Token != "dev-tok" {
			t.Errorf("unexpected request %+v", req)
		}
		return &protocol.CtrlResponse{
			OK: true, Status: "approved", KickReason: "kr", BanReason: "br", KickExpires: "ke", Pin: "ab",
		}, nil
	})
	t.Cleanup(func() { SetControlChannel(nil) })

	cfg := &config.ClientConf{ServerAddr: "unreachable.test:443", Fingerprint: ""}
	status, kickReason, banReason, kickExpires, err := checkTokenStatus(cfg, "dev-tok", false)
	if err != nil {
		t.Fatalf("checkTokenStatus: %v", err)
	}
	if status != "approved" || kickReason != "kr" || banReason != "br" || kickExpires != "ke" {
		t.Fatalf("status = %q %q %q %q", status, kickReason, banReason, kickExpires)
	}
}

// TestCheckTokenStatusNoPlainForApproved: with no control channel and no
// pinned client (bogus fingerprint), a non-bootstrap poll must refuse
// rather than leak the token over system-trusted TLS.
func TestCheckTokenStatusNoPlainForApproved(t *testing.T) {
	SetControlChannel(nil)
	cfg := &config.ClientConf{ServerAddr: "unreachable.test:443", Fingerprint: ""}
	if _, _, _, _, err := checkTokenStatus(cfg, "live-token", false); err == nil {
		t.Fatal("approved-state poll must not fall back to plain HTTPS")
	}
}
