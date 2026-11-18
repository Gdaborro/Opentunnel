//go:build windows && netenvfixture

package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

type editionFixtureInfo struct {
	Version      string `json:"version"`
	Edition      string `json:"edition"`
	Preview      string `json:"unreleased_local_preview"`
	State        string `json:"state_directory_name"`
	NetworkState string `json:"network_state_directory_name"`
	Asset        string `json:"windows_update_asset"`
	OwnServer    bool   `json:"own_server_configuration_required"`
}

func genericEditionFixture(t *testing.T) string {
	t.Helper()
	path := os.Getenv("OTU_TEST_GENERIC_CLIENT_BINARY")
	if path == "" {
		t.Skip("set OTU_TEST_GENERIC_CLIENT_BINARY to a separately built netenvfixture,genericclient executable")
	}
	return requireFixtureClientBinary(t, path)
}

func runEditionFixture(t *testing.T, binary, dir string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = dir, os.Environ(), strings.NewReader("\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("isolated client edition command failed", err, string(out))
	}
	return out
}

func preserveHostedIdentity(t *testing.T, app string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for name, raw := range map[string]string{"device.json": "synthetic original identity; never loaded", "device_ssh": "synthetic original private-key evidence", "ban.json": "synthetic original ban; never reset", "approved.flag": "synthetic original approval"} {
		path := filepath.Join(app, "opentunnel", name)
		if err := privatefile.WriteNew(path, []byte(raw)); err != nil {
			t.Fatal(err)
		}
		files[path] = []byte(raw)
	}
	return files
}

func checkPreservedFiles(t *testing.T, files map[string][]byte) {
	t.Helper()
	for path, before := range files {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("edition touched another operator's credential/ban file %s: %v", filepath.Base(path), err)
		}
	}
}

func TestGenericEditionHasNoHostedDefaultsAndRefusesUnconfiguredFirstRun(t *testing.T) {
	binary := genericEditionFixture(t)
	dir := t.TempDir()
	app := filepath.Join(dir, "appdata")
	t.Setenv("LOCALAPPDATA", app)
	settings := filepath.Join(dir, "network-fixture.json")
	t.Setenv("OTU_NETENV_FIXTURE", settings)
	original := proxyFixture{Keys: map[string]map[string]fixtureValue{fixtureWinINET: {"ProxyEnable": {Exists: true, Kind: 4, Integer: 0}, "ProxyServer": fixtureString("original-company-proxy.invalid:9000")}}}
	writeProxyFixture(t, settings, original)
	before := preserveHostedIdentity(t, app)
	infoRaw := runEditionFixture(t, binary, dir, "--build-info")
	var info editionFixtureInfo
	if err := json.Unmarshal(infoRaw, &info); err != nil || info.Edition != "generic" || !info.OwnServer || info.State != "opentunnel-generic" || info.NetworkState != "opentunnel" || info.Asset != "otu-client-generic-windows-amd64.exe" {
		t.Fatal("generic binary has wrong edition declaration", err)
	}
	if _, err := os.Lstat(filepath.Join(app, "opentunnel-generic")); !os.IsNotExist(err) {
		t.Fatal("read-only build info minted generic state", err)
	}
	image := filepath.Join(dir, "otu-client.exe")
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, hosted := range []string{"cdn.aborro.dev", "git.aborro.dev", "e86816f5e328d6d705b5594e64e7229276a639a264ca51db7916dc3c826aeac1"} {
		if bytes.Contains(raw, []byte(hosted)) {
			t.Fatal("generic executable contains hosted bootstrap trust/routing")
		}
	}
	if err := os.WriteFile(image, raw, 0700); err != nil {
		t.Fatal(err)
	}
	out := runEditionFixture(t, image, dir)
	if !bytes.Contains(out, []byte("Client startup was refused")) {
		t.Fatal("generic first run attempted to run without its own server", string(out))
	}
	config, err := os.ReadFile(filepath.Join(dir, "client.toml"))
	if err != nil || !bytes.Contains(config, []byte(`server_addr = ""`)) || bytes.Contains(config, []byte("aborro.dev")) {
		t.Fatal("generic first run did not leave an incomplete self-hosting template", err)
	}
	for _, name := range []string{"device.json", "device_ssh", "approved.flag", "device-key-established.flag"} {
		if _, err := os.Lstat(filepath.Join(app, "opentunnel-generic", name)); !os.IsNotExist(err) {
			t.Fatal("unconfigured generic startup created credentials", name, err)
		}
	}
	f, err := readProxyFixture(settings)
	if err != nil || !reflect.DeepEqual(f.Keys, original.Keys) {
		t.Fatal("unconfigured generic startup changed proxy settings", err)
	}
	checkPreservedFiles(t, before)
}

func TestClientEditionsShareNetworkLeaseButNeverShareCredentials(t *testing.T) {
	binary := genericEditionFixture(t)
	dir := t.TempDir()
	app := filepath.Join(dir, "appdata")
	t.Setenv("LOCALAPPDATA", app)
	settings := filepath.Join(dir, "network-fixture.json")
	t.Setenv("OTU_NETENV_FIXTURE", settings)
	before := preserveHostedIdentity(t, app)
	networkDir := filepath.Join(app, "opentunnel")
	snapshot := filepath.Join(networkDir, "snapshot.json")
	legacy := []byte(`{"proxy_enable":0,"proxy_server":{"exists":false},"proxy_override":{"exists":false},"autoconfig_url":{"exists":false},"otu_applied_server":"127.0.0.1:18080"}`)
	if err := privatefile.Write(snapshot, legacy); err != nil {
		t.Fatal(err)
	}
	writeProxyFixture(t, settings, proxyFixture{Keys: map[string]map[string]fixtureValue{fixtureWinINET: {"ProxyEnable": {Exists: true, Kind: 4, Integer: 1}, "ProxyServer": fixtureString("127.0.0.1:18080"), "ProxyOverride": fixtureString("localhost;127.0.0.1;<local>")}}})
	leasePath, err := windows.UTF16PtrFromString(filepath.Join(networkDir, "network-settings.lease"))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := windows.CreateFile(leasePath, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if lease != windows.InvalidHandle {
			_ = windows.CloseHandle(lease)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--restore")
	cmd.Dir, cmd.Env = dir, os.Environ()
	out, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(out, []byte("settings lease")) {
		t.Fatal("generic recovery bypassed the existing edition's network ownership", err, string(out))
	}
	after, err := os.ReadFile(snapshot)
	if err != nil || !bytes.Equal(after, legacy) {
		t.Fatal("lease conflict discarded recovery journal", err)
	}
	if err := windows.CloseHandle(lease); err != nil {
		t.Fatal(err)
	}
	lease = windows.InvalidHandle
	runEditionFixture(t, binary, dir, "--restore")
	if _, err := os.Lstat(snapshot); !os.IsNotExist(err) {
		t.Fatal("generic edition could not recover shared orphan network state", err)
	}
	checkPreservedFiles(t, before)
}

func TestGenericEditionUsesConfiguredLoopbackServerAndItsOwnApprovedIdentity(t *testing.T) {
	binary := genericEditionFixture(t)
	dir := t.TempDir()
	app := filepath.Join(dir, "appdata")
	t.Setenv("LOCALAPPDATA", app)
	settings := filepath.Join(dir, "network-fixture.json")
	t.Setenv("OTU_NETENV_FIXTURE", settings)
	writeProxyFixture(t, settings, proxyFixture{Keys: map[string]map[string]fixtureValue{fixtureWinINET: {}}})
	before := preserveHostedIdentity(t, app)
	store := &client.TokenStore{Dir: filepath.Join(app, "opentunnel-generic")}
	seedFixtureIdentity(t, store, "generic-edition-fixture")
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	store.MarkApproved(device.Fingerprint)
	db, err := panel.Open(filepath.Join(dir, "synthetic-panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'generic-fixture','approved',datetime('now'),datetime('now'),?,'generic-fixture')`, device.Token, pub); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/token/", panel.New(db, panel.NewAuth(db), false).Handler())
	mux.Handle("/", server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true}))
	relay := httptest.NewTLSServer(mux)
	defer relay.Close()
	proxyAddr := releaseFreePort(t)
	cfg := filepath.Join(dir, "client.toml")
	config := fmt.Sprintf("server_addr = %q\nfingerprint = %q\nsocks_addr = \"\"\nhttp_addr = %q\nprofile = \"fast\"\nauto_update = false\nh3_tier = false\nech = false\nfallback_ssh = false\n", relay.Listener.Addr().String(), hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw)), proxyAddr)
	if err := os.WriteFile(cfg, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", cfg)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, os.Environ(), io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("configured generic executable did not start its own proxy")
		}
		time.Sleep(20 * time.Millisecond)
	}
	payload := bytes.Repeat([]byte("generic-own-server-fixture"), 8192)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer origin.Close()
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://" + proxyAddr) }}}
	defer hc.CloseIdleConnections()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	response, err := hc.Get("http://localhost:" + port)
	if err != nil {
		t.Fatal("configured generic proxy transfer failed", err)
	}
	raw, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || !bytes.Equal(raw, payload) {
		t.Fatal("configured generic transfer lost bytes", err)
	}
	policy, err := db.AccessPolicy(device.Token)
	if err != nil || policy.UsedBytes < int64(len(payload)) {
		t.Fatal("generic transfer bypassed operator authentication/accounting", err)
	}
	checkPreservedFiles(t, before)
}
