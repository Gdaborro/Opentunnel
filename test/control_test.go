package test

import (
	"context"
	"testing"

	"opentunnel/internal/client"
	"opentunnel/internal/protocol"
)

// TestControlChannelStatusAndHealth proves the in-band control stream
// (v0.9.23): status and health ride the authenticated mux session, the
// panel DB records them, and every response carries the relay's current
// leaf pin so clients survive certificate rotation. Unknown tokens mirror
// the HTTPS 404 contract (status "") so purged devices re-register.
func TestControlChannelStatusAndHealth(t *testing.T) {
	addr, fp, db := startPanelServer(t)
	// The device token this machine's client presents (its own store).
	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen) VALUES(?,?,?,'approved',datetime('now'),datetime('now'))`,
		device.Token, device.Fingerprint, "ctrl-test-device"); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	cl := panelClient(addr, fp)

	resp, err := cl.CtrlExchange(context.Background(), protocol.CtrlRequest{Op: "status", Token: device.Token})
	if err != nil {
		t.Fatalf("ctrl status: %v", err)
	}
	if !resp.OK || resp.Status != "approved" {
		t.Fatalf("status resp = %+v", resp)
	}
	if resp.Pin != fp {
		t.Fatalf("pin announcement = %q, want the relay's current leaf pin %q", resp.Pin, fp)
	}
	// In-band ssh-tier dial-host learning: every control response carries
	// the relay's announced ssh target so the tier survives CDN fronting
	// without per-device config updates.
	if resp.SSHHost != "git.aborro.dev" {
		t.Fatalf("ssh host announcement = %q, want git.aborro.dev", resp.SSHHost)
	}

	resp, err = cl.CtrlExchange(context.Background(), protocol.CtrlRequest{
		Op: "health", Token: device.Token, Version: "v0.9.23-test", OS: "windows", Arch: "amd64",
	})
	if err != nil {
		t.Fatalf("ctrl health: %v", err)
	}
	if !resp.OK {
		t.Fatalf("health resp = %+v", resp)
	}
	var ver string
	if err := db.QueryRow(`SELECT version FROM device_health WHERE token=?`, device.Token).Scan(&ver); err != nil || ver != "v0.9.23-test" {
		t.Fatalf("device_health version = %q err=%v (want v0.9.23-test)", ver, err)
	}

	resp, err = cl.CtrlExchange(context.Background(), protocol.CtrlRequest{Op: "status", Token: "no-such-token"})
	if err != nil {
		t.Fatalf("ctrl status unknown: %v", err)
	}
	if !resp.OK || resp.Status != "" {
		t.Fatalf("unknown token must mirror the HTTPS 404 contract (ok+empty), got %+v", resp)
	}
}
