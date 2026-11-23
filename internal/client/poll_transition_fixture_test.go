//go:build netenvfixture

package client

import (
	"context"
	"os"
	"testing"

	"opentunnel/internal/config"
	"opentunnel/internal/protocol"
)

// Default-scope ban adapters must be compile-time registry-free for this test.
func TestTrustedApprovalIsNotSuppressedByPriorUnverifiedApproval(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.BanPath(), []byte(`{"reason":"synthetic existing ban"}`), 0600); err != nil {
		t.Fatal(err)
	}
	SetControlChannel(func(context.Context, protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
		return &protocol.CtrlResponse{OK: true, Status: "approved"}, nil
	})
	t.Cleanup(func() { SetControlChannel(nil) })
	device := &DeviceIdentity{Token: "synthetic-status-token", Fingerprint: "synthetic-status-fingerprint"}
	last := "approved:unverified"
	approved := 0
	checkOnceContext(t.Context(), &config.ClientConf{}, device, nil, nil, func() { approved++ }, &last)
	if last != "approved" || approved != 1 || !store.EverApproved(device.Fingerprint) {
		t.Fatal("trusted approval transition was lost", last, approved)
	}
	if _, err := os.Lstat(store.BanPath()); !os.IsNotExist(err) {
		t.Fatal("trusted unban retained stale local marker", err)
	}
	checkOnceContext(t.Context(), &config.ClientConf{}, device, nil, nil, func() { approved++ }, &last)
	if approved != 1 {
		t.Fatal("unchanged trusted verdict repeated admission callback", approved)
	}
}
