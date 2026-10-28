// Package security is the historical-attack regression suite: every PoC
// from the audit rounds lives here as a permanent test. CI runs it on
// every push — if an old attack ever works again, the build goes red.
package security

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// setup runs the real relay handler over TLS with a real panel DB,
// seeding the local device identity as an approved peer with its pubkey.
func setup(t *testing.T) (addr string, db *panel.DB, token string) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())

	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}

	db, err = panel.Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen)
		VALUES(?,?,?,?,'approved',datetime('now'),datetime('now'))`,
		dev.Token, dev.Fingerprint, "sec-test", strings.TrimSpace(pub)); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	cert, _, err := transport.LoadOrCreateCert(tmp+"/c.pem", tmp+"/k.pem", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: server.Handler(server.Options{
			Token:                  "sec-suite-master",
			PanelDB:                db,
			AllowRestrictedTargets: true,
		}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), db, dev.Token
}

// rawV4Handshake dials the relay over WS and sends a v4 handshake for tok,
// returning the server's status byte. This is the auditor's round-four
// downgrade PoC shape.
func rawV4Handshake(t *testing.T, addr, tok string) byte {
	t.Helper()
	httpc := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
			if err := tc.Handshake(); err != nil {
				return nil, err
			}
			return tc, nil
		},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://"+addr+"/api/v1/stream", &websocket.DialOptions{HTTPClient: httpc})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteHandshake(conn, tok); err != nil {
		t.Fatalf("v4 handshake write: %v", err)
	}
	_, status, err := protocol.ReadHandshakeStatus(conn)
	if err != nil {
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "reset") {
			return 255 // silent close = treated as refusal by callers below
		}
		t.Fatalf("status read: %v", err)
	}
	return status
}

// TestV4DowngradeRefusedAfterV5 (audit round four, HIGH-MED): a token
// that has completed one signature-verified v5 session must be refused
// when re-presented as a v4 handshake — the stolen-token downgrade.
func TestV4DowngradeRefusedAfterV5(t *testing.T) {
	addr, db, tok := setup(t)

	// A legitimate v5 session first (the client signs with its device key).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()
	th, tp, _ := net.SplitHostPort(target.Listener.Addr().String())
	taddr, _ := protocol.ParseAddress(th, atoi(t, tp))

	real := transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: addr, Insecure: true})
	cl := client.NewWithOptions(real, client.Options{Mux: true, DialTimeout: 10 * time.Second})
	conn, err := cl.DialTunnel(context.Background(), taddr)
	if err != nil {
		t.Fatalf("legit v5 session: %v", err)
	}
	conn.Close()

	if !db.V5Seen(tok) {
		t.Fatal("relay must latch v5_seen after a verified v5 session")
	}

	// The downgrade PoC: raw v4 handshake with the same token.
	status := rawV4Handshake(t, addr, tok)
	if status != protocol.StatusBadToken {
		t.Fatalf("v4 downgrade: status=%d, want BadToken", status)
	}
	found := false
	for _, a := range db.Alerts(20) {
		if strings.Contains(a.Message, "downgrade") {
			found = true
		}
	}
	if !found {
		t.Fatal("downgrade attempt must raise a security alert")
	}
}

// TestV4AdmittedForNeverUpgradedPeer: the migration window stays open per
// identity — a peer that has never done v5 keeps working over v4.
func TestV4AdmittedForNeverUpgradedPeer(t *testing.T) {
	addr, db, _ := setup(t)
	const fresh = "fresh-peer-token-1234567890"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen)
		VALUES(?,'fp2','approved',datetime('now'),datetime('now'))`, fresh); err != nil {
		t.Fatal(err)
	}
	status := rawV4Handshake(t, addr, fresh)
	if status != protocol.StatusOK {
		t.Fatalf("never-upgraded peer v4: status=%d, want OK", status)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("bad port %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
