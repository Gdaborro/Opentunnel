package test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// startPanelServer runs a TLS relay backed by a real panel DB. The master
// token is NOT accepted at the handshake (AllowLegacyMaster off) — devices
// must be approved in the panel. Returns the relay address, its cert
// fingerprint, and the DB.
func startPanelServer(t *testing.T) (addr, fp string, db *panel.DB) {
	t.Helper()
	var err error
	db, err = panel.Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	cert, certFP, err := transport.LoadOrCreateCert(tmp+"/c.pem", tmp+"/k.pem", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: server.Handler(server.Options{
			Token:                  "master-secret-not-in-exe",
			PanelDB:                db,
			AllowRestrictedTargets: true, // tests dial loopback targets
		}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { srv.Close() })
	t.Cleanup(func() { db.Close() })
	return ln.Addr().String(), certFP, db
}

// panelClient builds a client with NO shared token: it can only
// authenticate with its per-device token, exactly like a distributed exe.
func panelClient(addr, fp string) *client.Client {
	real := transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: addr, Fingerprint: fp})
	return client.NewWithOptions(real, client.Options{Mux: true, DialTimeout: 5 * time.Second})
}

func TestPanelPerDeviceAuth(t *testing.T) {
	addr, fp, db := startPanelServer(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "panel-auth-ok")
	}))
	defer target.Close()
	tgtHost, tgtPort, _ := net.SplitHostPort(target.Listener.Addr().String())
	port := atoi(t, tgtPort)
	dial := func() error {
		a, err := protocol.ParseAddress(tgtHost, port)
		if err != nil {
			return err
		}
		conn, err := panelClient(addr, fp).DialTunnel(context.Background(), a)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

	// The device token this machine's client presents (its own store).
	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}

	// 1. Unknown device → rejected and treated as pending (re-register path).
	var pend *client.PendingError
	if err := dial(); err == nil || !errors.As(err, &pend) {
		t.Fatalf("unknown device: want PendingError, got %v", err)
	}

	// 2. Register + approve → tunnel works with no shared token anywhere.
	db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen) VALUES(?,?,?,'approved',datetime('now'),datetime('now'))`,
		device.Token, device.Fingerprint, "test-device")
	if err := dial(); err != nil {
		t.Fatalf("approved device: %v", err)
	}

	// 3. Pending device → PendingError.
	db.Exec(`UPDATE peers SET status='pending' WHERE token=?`, device.Token)
	if err := dial(); err == nil || !errors.As(err, &pend) {
		t.Fatalf("pending device: want PendingError, got %v", err)
	}

	// 4. Banned identity → BlockedError, and the ban trumps row status:
	// even if the peers row is flipped back to approved, the device stays
	// banned until the identity ban is lifted.
	db.Exec(`UPDATE peers SET status='approved' WHERE token=?`, device.Token)
	db.BanIdentity(device.Token, "test ban")
	db.Exec(`UPDATE peers SET status='approved' WHERE token=?`, device.Token)
	if status, reason, _, _ := db.CheckToken(device.Token); status != "banned" || reason != "test ban" {
		t.Fatalf("identity ban must trump approved row: status=%s reason=%s", status, reason)
	}
	var blocked *client.BlockedError
	if err := dial(); err == nil || !errors.As(err, &blocked) {
		t.Fatalf("banned device: want BlockedError, got %v", err)
	}
	if !db.IdentityBanned(device.Fingerprint, "") {
		t.Fatal("fingerprint should be banned")
	}

	// 5. Unban identity → fingerprint ban cleared.
	db.UnbanIdentity(device.Token)
	if db.IdentityBanned(device.Fingerprint, "") {
		t.Fatal("fingerprint ban should be cleared")
	}
}
