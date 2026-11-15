package test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/panel"
	"opentunnel/internal/server"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
)

// Two TLS entry points use one actual local SQLite authority. This verifies
// failover, shared approval/accounting and operator isolation without claiming
// independent remote databases are synchronized or probing public servers.
func TestTrustedPoolTwoEntriesShareApprovalAndAccounting(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	_, operator, _ := ed25519.GenerateKey(rand.Reader)
	poolID := serverpool.OperatorID(operator.Public().(ed25519.PublicKey))
	db, err := panel.Open(filepath.Join(t.TempDir(), "authority.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ph, err := panel.New(db, panel.NewAuth(db), false).WithServerPool(poolID, false)
	if err != nil {
		t.Fatal(err)
	}
	info, err := db.BindServerPool(poolID, false)
	if err != nil {
		t.Fatal(err)
	}
	var disabled [2]atomic.Bool
	entries := make([]*httptest.Server, 2)
	nodes := make([]serverpool.Node, 2)
	for i := range 2 {
		mux := http.NewServeMux()
		mux.Handle("/api/token/", ph.Handler())
		mux.Handle("/", server.Handler(server.Options{PanelDB: db, PoolID: poolID, AuthorityID: info.AuthorityID, WSPath: "/stream", AllowRestrictedTargets: true}))
		entries[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == serverpool.InfoPath && i == 1 {
				time.Sleep(60 * time.Millisecond)
			}
			if disabled[i].Load() {
				http.Error(w, "synthetic offline entry", 503)
				return
			}
			mux.ServeHTTP(w, r)
		}))
		defer entries[i].Close()
		nodes[i] = serverpool.Node{ID: []string{"entry-a", "entry-b"}[i], Name: []string{"Entry A", "Entry B"}[i], Address: []string{"entry-a.example:443", "entry-b.example:443"}[i], DialAddress: entries[i].Listener.Addr().String(), Pins: []string{hex.EncodeToString(transport.FingerprintCert(entries[i].Certificate().Raw))}, WSPath: "/stream"}
	}
	now := time.Now()
	profile := serverpool.Profile{Name: "Synthetic shared pool", AuthorityID: info.AuthorityID, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ApprovalRequired: true, Nodes: nodes}
	if err := profile.Sign(operator, now); err != nil {
		t.Fatal(err)
	}
	selector, err := client.NewPoolSelector(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	cfg := &config.ClientConf{Pool: &profile, PoolNode: selector.Current}
	store, err := client.NewPoolTokenStore(poolID)
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.EnrollPool(t.Context(), cfg, device, nil); err != nil {
		t.Fatal(err)
	}
	if status, _, _, _, err := client.TokenStatus(cfg, device.Token); err != nil || status != "pending" {
		t.Fatal("signed status did not preserve pending approval", status, err)
	}
	dialer := client.NewAdaptive("do-not-use-default-secret", transport.WSTLSOptions{}, "fast", 5*time.Second)
	dialer.UseTrustedPool(selector)
	dialer.EnableMux()
	defer dialer.Close()
	payload := bytes.Repeat([]byte("shared-authority-payload"), 4096)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer origin.Close()
	urlHost := strings.TrimPrefix(origin.URL, "http://")
	host, port, err := net.SplitHostPort(urlHost)
	if err != nil {
		t.Fatal(err)
	}
	target, err := parseAddrForTest(host, port)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := dialer.DialTunnel(t.Context(), target); err == nil {
		c.Close()
		t.Fatal("login-free pending device passed traffic without approval")
	}
	if err := db.PeerStateAction(device.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	if status, _, _, _, err := client.TokenStatus(cfg, device.Token); err != nil || status != "approved" {
		t.Fatal(status, err)
	}
	request := func() {
		c, err := dialer.DialTunnel(t.Context(), target)
		if err != nil {
			t.Fatal("approved pool dial", err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: synthetic-origin\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || !bytes.Equal(raw, payload) {
			t.Fatal("pool payload mismatch", err)
		}
	}
	request()
	first := selector.Current().ID
	disabled[0].Store(first == "entry-a")
	disabled[1].Store(first == "entry-b")
	_ = dialer.Close()
	dialer = client.NewAdaptive("", transport.WSTLSOptions{}, "fast", 5*time.Second)
	dialer.UseTrustedPool(selector)
	dialer.EnableMux()
	defer dialer.Close()
	request()
	if selector.Current().ID == first {
		t.Fatal("failed entry not replaced inside pool")
	}
	p, err := db.AccessPolicy(device.Token)
	if err != nil || p.UsedBytes < int64(2*len(payload)) {
		t.Fatal("entries did not share accounting", p.UsedBytes, err)
	}
	otherID := strings.Repeat("f", 64)
	foreign, err := client.NewPoolTokenStore(otherID)
	if err != nil {
		t.Fatal(err)
	}
	foreignDevice, err := foreign.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if db.KnownPeer(foreignDevice.Token) || foreignDevice.Token == device.Token {
		t.Fatal("operator identity inherited approval")
	}
	if err := db.PeerStateAction(device.Token, "ban", "synthetic pool ban", "permanent"); err != nil {
		t.Fatal(err)
	}
	if c, err := dialer.DialTunnel(t.Context(), target); err == nil {
		c.Close()
		t.Fatal("warm mux bypassed shared revocation")
	}
}
