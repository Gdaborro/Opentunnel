//go:build windows

package test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

func TestFixtureClientTrustedPoolImportSelectionAndTraffic(t *testing.T) {
	fixturePoolClientTraffic(t, false)
}

func TestFixtureClientChannelPoolImportSelectionAndTraffic(t *testing.T) {
	fixturePoolClientTraffic(t, true)
}

func fixturePoolClientTraffic(t *testing.T, channelAuth bool) {
	binary := fixtureClientBinary(t) // compile-time registry/ban adapters must be absent
	dir := t.TempDir()
	appData := filepath.Join(dir, "appdata")
	t.Setenv("LOCALAPPDATA", appData)
	fixturePath := filepath.Join(dir, "synthetic-settings.json")
	t.Setenv("OTU_NETENV_FIXTURE", fixturePath)
	writeProxyFixture(t, fixturePath, proxyFixture{Keys: map[string]map[string]fixtureValue{fixtureWinINET: {}}})
	_, operator, _ := ed25519.GenerateKey(rand.Reader)
	poolID := serverpool.OperatorID(operator.Public().(ed25519.PublicKey))
	db, err := panel.Open(filepath.Join(dir, "pool.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ph, err := panel.New(db, panel.NewAuth(db), false).WithServerPoolAuthentication(poolID, false, channelAuth)
	if err != nil {
		t.Fatal(err)
	}
	info, err := db.BindServerPoolAuthentication(poolID, false, channelAuth)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/token/", ph.Handler())
	options := server.Options{PanelDB: db, PoolID: poolID, AuthorityID: info.AuthorityID, WSPath: "/stream", AllowRestrictedTargets: true}
	innerCert := innerTestCert(t)
	if channelAuth {
		options.InnerTLSCertificate = &innerCert
		options.RequireInnerTLS = true
		options.RequireChannelAuth = true
	}
	mux.Handle("/", server.Handler(options))
	relay := httptest.NewTLSServer(mux)
	defer relay.Close()
	now := time.Now()
	p := serverpool.Profile{Name: "Synthetic executable pool", AuthorityID: info.AuthorityID, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ApprovalRequired: true, Nodes: []serverpool.Node{{ID: "entry", Name: "Entry", Address: "entry.example:443", DialAddress: relay.Listener.Addr().String(), Pins: []string{hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw))}, WSPath: "/stream"}}}
	if channelAuth {
		p.RequireChannelAuth = true
		p.Nodes[0].InnerTLSPins = []string{protocol.PublicKeyPin(innerCert.Leaf)}
	}
	if err := p.Sign(operator, now); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "pool.json")
	if err := serverpool.Export(profilePath, p, now); err != nil {
		t.Fatal(err)
	}
	runCommand := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Env = os.Environ()
		cmd.Dir = dir
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("profile command failed: %v (%s)", err, raw)
		}
		return string(raw)
	}
	runCommand("--pool-import", profilePath, "--accept-pool", poolID)
	runCommand("--pool-select", poolID)
	if output := runCommand("--pool-list"); !strings.Contains(output, poolID) || !strings.Contains(output, p.Name) {
		t.Fatal("executable pool inventory omitted imported trust")
	}
	root := filepath.Join(appData, version.ProductName)
	for _, name := range []string{"device.json", "device_ssh", "crash.log", "snapshot.json", "selected-config.toml"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("standalone profile command touched runtime state", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "client.toml")); !os.IsNotExist(err) {
		t.Fatal("profile command rewrote client config")
	}
	proxyAddr := releaseFreePort(t)
	cfgPath := filepath.Join(dir, "selected-config.toml")
	// Every default-operator transport setting is deliberately unusable.
	// The imported profile must override these without copying its credentials.
	cfg := fmt.Sprintf("server_addr = \"default.invalid:443\"\ntoken = \"synthetic-default-master-not-sent\"\nfingerprint = %q\nsocks_addr = %q\nhttp_addr = \"\"\nprofile = \"fast\"\nauto_update = false\nh3_tier = true\nfallback_ssh = true\nssh_key = \"foreign-default-key\"\nssh_host_keys = \"SHA256:foreign-default-pin\"\n", strings.Repeat("f", 64), proxyAddr)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "synthetic-client.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command(binary, "-c", cfgPath)
	cmd.Env = os.Environ()
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scoped, err := client.NewPoolTokenStore(poolID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	var device *client.DeviceIdentity
	for {
		if _, err := os.Stat(scoped.TokenPath()); err == nil {
			device, err = scoped.LoadOrCreate()
			if err == nil && db.KnownPeer(device.Token) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture client did not enroll from selected profile")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if policy, err := db.AccessPolicy(device.Token); err != nil || policy.Status != "pending" {
		t.Fatal("executable client bypassed manual approval", err)
	}
	if err := db.PeerStateAction(device.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	for {
		c, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture client did not expose local proxy")
		}
		time.Sleep(20 * time.Millisecond)
	}
	payload := bytes.Repeat([]byte("trusted-pool-executable"), 4096)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer origin.Close()
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext}}
	defer hc.CloseIdleConnections()
	// entry TCP override is 127.0.0.1; the loop guard intentionally dials
	// entry hosts directly. Use a distinct origin authority so this request
	// actually passes through the authenticated pool and its accounting.
	_, originPort, _ := net.SplitHostPort(origin.Listener.Addr().String())
	resp, err := hc.Get("http://localhost:" + originPort + "/")
	if err != nil {
		t.Fatal("selected pool executable traffic failed", err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("fixture payload changed", err)
	}
	policy, err := db.AccessPolicy(device.Token)
	if err != nil || policy.UsedBytes < int64(len(payload)) {
		t.Fatal("fixture bypassed authority/accounting", err)
	}
	if channelAuth && (!policy.ChannelSeen || !policy.ChannelVerified) {
		t.Fatal("fixture executable did not satisfy signed v6 authentication requirement")
	}
	status := runCommand("--status")
	if strings.Contains(status, device.Token) || strings.Contains(status, "synthetic-default-master-not-sent") {
		t.Fatal("read-only executable status leaked credentials")
	}
	for _, name := range []string{"device.json", "device_ssh", "ban.json", "pins.json", "ssh_host"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("pool client touched default operator identity/trust", name)
		}
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil || string(after) != cfg {
		t.Fatal("pool selection rewrote installed config")
	}
	f := waitFixture(t, fixturePath, func(f proxyFixture) bool { return !f.Keys[fixtureWinINET]["ProxyServer"].Exists })
	if f.Keys[fixtureWinINET]["ProxyEnable"].Integer != 0 {
		t.Fatal("manual pool fixture unexpectedly enabled system proxy")
	}
	t.Log("registry-free fixture executable imported/selected trust, enrolled pending, transmitted approved payload and kept default identity/config untouched")
}

func TestFixtureClientCorruptPoolStillRecoversPreviousProxyJournal(t *testing.T) {
	binary := fixtureClientBinary(t)
	dir := t.TempDir()
	app := filepath.Join(dir, "appdata")
	t.Setenv("LOCALAPPDATA", app)
	fixturePath := filepath.Join(dir, "synthetic-settings.json")
	t.Setenv("OTU_NETENV_FIXTURE", fixturePath)
	root, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefile.Write(filepath.Join(root.Dir, "selected-server-pool.json"), []byte(`{"id":"invalid-corrupt-selection"}`)); err != nil {
		t.Fatal(err)
	}
	legacy := map[string]any{"proxy_enable": 0, "proxy_server": map[string]any{"exists": true, "data": "original-proxy.invalid:9000"}, "proxy_override": map[string]any{"exists": true, "data": "original-bypass.invalid"}, "autoconfig_url": map[string]any{"exists": false}, "otu_applied_server": "127.0.0.1:18080"}
	raw, _ := json.Marshal(legacy)
	if err := privatefile.Write(filepath.Join(root.Dir, "snapshot.json"), raw); err != nil {
		t.Fatal(err)
	}
	writeProxyFixture(t, fixturePath, proxyFixture{Keys: map[string]map[string]fixtureValue{fixtureWinINET: {"ProxyEnable": {Exists: true, Kind: 4, Integer: 1}, "ProxyServer": fixtureString("127.0.0.1:18080"), "ProxyOverride": fixtureString("localhost;127.0.0.1;<local>")}}})
	cfgPath := filepath.Join(dir, "client.toml")
	cfg := "server_addr = \"must-not-connect.invalid:443\"\nprofile = \"fast\"\nauto_update = false\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", cfgPath)
	cmd.Env = os.Environ()
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("fixture startup recovery failed", err, string(output))
	}
	if !strings.Contains(string(output), "startup refused after orphan recovery") {
		t.Fatal("corrupt profile silently connected/fell back", string(output))
	}
	f, err := readProxyFixture(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if f.Keys[fixtureWinINET]["ProxyEnable"].Integer != 0 || f.Keys[fixtureWinINET]["ProxyServer"].Text != "original-proxy.invalid:9000" || f.Keys[fixtureWinINET]["ProxyOverride"].Text != "original-bypass.invalid" {
		t.Fatal("corrupt profile stranded previous settings", f)
	}
	if _, err := os.Stat(filepath.Join(root.Dir, "snapshot.json")); !os.IsNotExist(err) {
		t.Fatal("completed fixture recovery left active journal")
	}
	if _, err := os.Stat(root.TokenPath()); !os.IsNotExist(err) {
		t.Fatal("corrupt selection minted default identity")
	}
}
