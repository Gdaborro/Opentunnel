package test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"opentunnel/internal/authority"
	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
)

func authorityTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "dedicated authority fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestCentralAuthorityTwoIndependentRelaysShareApprovalQuotaAndFailClosed(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	_, operator, _ := ed25519.GenerateKey(rand.Reader)
	poolID := serverpool.OperatorID(operator.Public().(ed25519.PublicKey))
	db, err := panel.Open(filepath.Join(t.TempDir(), "central.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ph, err := panel.New(db, panel.NewAuth(db), false).WithServerPoolAuthentication(poolID, false, true)
	if err != nil {
		t.Fatal(err)
	}
	info, err := db.BindServerPoolAuthentication(poolID, false, true)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := authorityTestCertificate(t)
	nodeCerts := []tls.Certificate{authorityTestCertificate(t), authorityTestCertificate(t)}
	nodeInventory := authority.Nodes{Nodes: []authority.Node{{ID: "node-a", Pins: []string{protocol.PublicKeyPin(nodeCerts[0].Leaf)}}, {ID: "node-b", Pins: []string{protocol.PublicKeyPin(nodeCerts[1].Leaf)}}}}
	ah, err := authority.NewHandler(db, info, nodeInventory, ph.Handler())
	if err != nil {
		t.Fatal(err)
	}
	var partition atomic.Bool
	central := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if partition.Load() {
			http.Error(w, "fixture partition", 503)
			return
		}
		ah.ServeHTTP(w, r)
	}))
	central.TLS, err = authority.ServerTLS(serverCert, nodeInventory)
	if err != nil {
		t.Fatal(err)
	}
	central.EnableHTTP2 = true
	central.StartTLS()
	defer central.Close()
	entries := make([]*httptest.Server, 2)
	remotes := make([]*authority.Client, 2)
	nodes := make([]serverpool.Node, 2)
	var disabled [2]atomic.Bool
	for i := range 2 {
		remotes[i], err = authority.NewClient(authority.ClientOptions{URL: central.URL, PoolID: poolID, AuthorityID: info.AuthorityID, NodeID: nodeInventory.Nodes[i].ID, Certificate: nodeCerts[i], Pins: []string{protocol.PublicKeyPin(serverCert.Leaf)}})
		if err != nil {
			t.Fatal(err)
		}
		defer remotes[i].Close()
		if _, err := remotes[i].Info(t.Context()); err != nil {
			t.Fatal("mutual authority authentication failed", err)
		}
		inner := innerTestCert(t)
		relay := server.Handler(server.Options{PanelDB: remotes[i], PoolID: poolID, AuthorityID: info.AuthorityID, RequireInnerTLS: true, RequireChannelAuth: true, InnerTLSCertificate: &inner, WSPath: "/stream", AllowRestrictedTargets: true})
		mux := http.NewServeMux()
		mux.HandleFunc("/api/token/", func(w http.ResponseWriter, r *http.Request) {
			remotes[i].ForwardPublic(w, r, server.ResolveClientIP(r, false))
		})
		mux.Handle("/", relay)
		entries[i] = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if disabled[i].Load() {
				http.Error(w, "fixture node offline", 503)
				return
			}
			mux.ServeHTTP(w, r)
		}))
		defer entries[i].Close()
		nodes[i] = serverpool.Node{ID: nodeInventory.Nodes[i].ID, Name: nodeInventory.Nodes[i].ID, Address: []string{"node-a.example:443", "node-b.example:443"}[i], DialAddress: entries[i].Listener.Addr().String(), Pins: []string{hex.EncodeToString(transport.FingerprintCert(entries[i].Certificate().Raw))}, InnerTLSPins: []string{protocol.PublicKeyPin(inner.Leaf)}, WSPath: "/stream"}
	}
	now := time.Now()
	profile := serverpool.Profile{Name: "Synthetic central authority", AuthorityID: info.AuthorityID, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ApprovalRequired: true, RequireChannelAuth: true, Nodes: nodes}
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
	cfg := &config.ClientConf{Pool: &profile, PoolNode: selector.Current, RequireChannelAuth: true}
	store, _ := client.NewPoolTokenStore(poolID)
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.EnrollPool(t.Context(), cfg, device, nil); err != nil {
		t.Fatal("forwarded signed enrollment failed", err)
	}
	if status, _, _, _, err := client.TokenStatus(cfg, device.Token); err != nil || status != "pending" {
		t.Fatal("enrollment bypassed approval", status, err)
	}
	if err := db.PeerStateAction(device.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	for _, remote := range remotes {
		if p, err := remote.AccessPolicy(device.Token); err != nil || p.Status != "approved" || !p.Enrolled || !p.ChannelRequired {
			t.Fatal("remote authoritative policy mismatch", p.Status, err)
		}
	}
	dialer := client.NewAdaptive("unused-default-secret", transport.WSTLSOptions{}, "fast", 5*time.Second)
	dialer.UseTrustedPool(selector)
	dialer.EnableMux()
	defer dialer.Close()
	payload := bytes.Repeat([]byte("independent-relay-payload"), 4096)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	target, err := parseAddrForTest(host, port)
	if err != nil {
		t.Fatal(err)
	}
	request := func() error {
		c, err := dialer.DialTunnel(t.Context(), target)
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"); err != nil {
			return err
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, payload) {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	if err := request(); err != nil {
		t.Fatal("remote-authority traffic", err)
	}
	first := selector.Current().ID
	// A fresh mux client makes actual independent-node failover mandatory,
	// rather than accidentally continuing over a warm session to the old node.
	_ = dialer.Close()
	disabled[0].Store(first == "node-a")
	disabled[1].Store(first == "node-b")
	dialer = client.NewAdaptive("", transport.WSTLSOptions{}, "fast", 5*time.Second)
	dialer.UseTrustedPool(selector)
	dialer.EnableMux()
	defer dialer.Close()
	if err := request(); err != nil {
		t.Fatal("independent node failover", err)
	}
	if selector.Current().ID == first {
		t.Fatal("did not switch independent nodes")
	}
	p, err := db.AccessPolicy(device.Token)
	if err != nil || p.UsedBytes < int64(2*len(payload)) || !p.ChannelSeen {
		t.Fatal("nodes did not share usage/authentication latch", p.UsedBytes, err)
	}
	partition.Store(true)
	if err := request(); err == nil {
		t.Fatal("authority partition permitted new data using stale/local policy")
	}
	partition.Store(false)
	if err := db.PeerStateAction(device.Token, "ban", "fixture revocation", ""); err != nil {
		t.Fatal(err)
	}
	if err := request(); err == nil {
		t.Fatal("central revocation did not stop traffic")
	}
	// A node cannot use its credential to enter admin or spoof another node.
	clientTLS, err := authority.ClientTLS(nodeCerts[0], "", []string{protocol.PublicKeyPin(serverCert.Leaf)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: clientTLS}
	defer tr.CloseIdleConnections()
	httpClient := &http.Client{Transport: tr, Timeout: time.Second}
	for _, test := range []struct{ path, node string }{{"/admin/api/peers", "node-a"}, {authority.APIPath + "info", "node-b"}} {
		req, _ := http.NewRequest(http.MethodPost, central.URL+test.path, strings.NewReader(`{}`))
		req.Header.Set("X-Otu-Node", test.node)
		req.Header.Set("X-Otu-Pool", poolID)
		req.Header.Set("X-Otu-Authority", info.AuthorityID)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatal("node credential granted administrator/other-node authority", test.path)
		}
	}
}
