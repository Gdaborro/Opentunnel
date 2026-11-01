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

	// 1.0.1 identity binding: the wire token field is ignored entirely —
	// the verdict always answers for the token that authenticated the
	// session, so even a nonsense wire token yields the session's own
	// status. (The 404-mirror contract now applies when the SESSION token
	// is unknown; see TestControlChannelIdentityBinding.)
	resp, err = cl.CtrlExchange(context.Background(), protocol.CtrlRequest{Op: "status", Token: "no-such-token"})
	if err != nil {
		t.Fatalf("ctrl status unknown: %v", err)
	}
	if !resp.OK || resp.Status != "approved" {
		t.Fatalf("wire token must be ignored (session identity answers), got %+v", resp)
	}
}

// TestControlChannelIdentityBinding (1.0.1): the in-band control channel
// must answer for the token that AUTHENTICATED the session, never for the
// token string the client puts on the wire — before this fix any approved
// device could read another peer's status/ban reason and write health
// rows under arbitrary token strings.
func TestControlChannelIdentityBinding(t *testing.T) {
	addr, fp, db := startPanelServer(t)
	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen) VALUES(?,?,?,'approved',datetime('now'),datetime('now'))`,
		device.Token, device.Fingerprint, "identity-a"); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	const victim = "victim-token-0123456789abcdef"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen) VALUES(?,?,?,'pending',datetime('now'),datetime('now'))`,
		victim, "fp-victim", "identity-b"); err != nil {
		t.Fatalf("seed victim: %v", err)
	}

	cl := panelClient(addr, fp)

	// Status with the victim's token on the wire: must answer for the
	// SESSION identity (approved), not the victim (pending).
	resp, err := cl.CtrlExchange(context.Background(), protocol.CtrlRequest{Op: "status", Token: victim})
	if err != nil {
		t.Fatalf("ctrl status: %v", err)
	}
	if resp.Status != "approved" {
		t.Fatalf("status answered for the wire token: got %q, want the session identity's approved", resp.Status)
	}

	// Health written under the victim's token must land on the session
	// identity — and never mint a row for the victim string.
	resp, err = cl.CtrlExchange(context.Background(), protocol.CtrlRequest{
		Op: "health", Token: victim, Version: "v1.0.1-binding-test", OS: "windows", Arch: "amd64",
	})
	if err != nil || !resp.OK {
		t.Fatalf("ctrl health: err=%v resp=%+v", err, resp)
	}
	var ver string
	if err := db.QueryRow(`SELECT version FROM device_health WHERE token=?`, device.Token).Scan(&ver); err != nil || ver != "v1.0.1-binding-test" {
		t.Fatalf("session identity health row = %q err=%v", ver, err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM device_health WHERE token=?`, victim).Scan(&n); err != nil || n != 0 {
		t.Fatalf("victim health rows = %d err=%v, want 0", n, err)
	}
}

// TestControlHostileNetIntel (v1.1.x): a health report carrying the
// client's hostile-network flag (its adaptive stealth saw TLS
// interception) must raise a throttled sentinel alert — once, not once
// per health report.
func TestControlHostileNetIntel(t *testing.T) {
	addr, fp, db := startPanelServer(t)
	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen) VALUES(?,?,?,'approved',datetime('now'),datetime('now'))`,
		device.Token, device.Fingerprint, "hostile-reporter"); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	cl := panelClient(addr, fp)
	send := func() {
		resp, err := cl.CtrlExchange(context.Background(), protocol.CtrlRequest{
			Op: "health", Token: device.Token, Version: "v1.1.0", OS: "windows", Arch: "amd64",
			HostileNet: true,
		})
		if err != nil || !resp.OK {
			t.Fatalf("ctrl health: err=%v resp=%+v", err, resp)
		}
	}
	send()
	send()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind='sentinel' AND message LIKE '%TLS interception%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("hostile-net alert rows = %d, want exactly 1 (throttled)", n)
	}
}
