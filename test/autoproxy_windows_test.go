//go:build windows

package test

import (
	"bytes"
	"crypto/rand"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"opentunnel/internal/version"
)

const fixtureWinINET = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var fixturePolicyPaths = []string{`Software\Policies\Google\Chrome`, `Software\Policies\Microsoft\Edge`, `Software\Policies\BraveSoftware\Brave`, `Software\Policies\Vivaldi`, `Software\Policies\Chromium`}

type fixtureValue struct {
	Exists  bool   `json:"exists"`
	Kind    uint32 `json:"kind,omitempty"`
	Text    string `json:"text,omitempty"`
	Integer uint64 `json:"integer,omitempty"`
}

type proxyFixture struct {
	Keys               map[string]map[string]fixtureValue `json:"keys"`
	ReadOnlyPolicies   bool                               `json:"read_only_policies,omitempty"`
	DenyMandatoryApply bool                               `json:"deny_mandatory_apply,omitempty"`
	DenyPolicyRestore  bool                               `json:"deny_policy_restore,omitempty"`
}

func fixtureString(text string) fixtureValue { return fixtureValue{Exists: true, Kind: 1, Text: text} }

func seedFixtureIdentity(t *testing.T, store *client.TokenStore, name string) {
	t.Helper()
	// Seed before LoadOrCreate: generating a production identity would query
	// the real ban registry and machine fingerprint even in the test parent.
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"token": base64.RawURLEncoding.EncodeToString(token), "fingerprint": name + "-fingerprint", "device_name": name})
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefile.WriteNew(store.TokenPath(), raw); err != nil {
		t.Fatal(err)
	}
}

func writeProxyFixture(t *testing.T, path string, f proxyFixture) {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := retryProxyFixtureIO(func() error { return privatefile.Write(path, raw) }); err != nil {
		t.Fatal(err)
	}
}

func readProxyFixture(path string) (proxyFixture, error) {
	f := proxyFixture{}
	var raw []byte
	err := retryProxyFixtureIO(func() error {
		var err error
		raw, err = privatefile.Read(path, 1<<20)
		return err
	})
	if err != nil {
		return f, err
	}
	err = json.Unmarshal(raw, &f)
	return f, err
}

func retryProxyFixtureIO(operation func() error) error {
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		err = operation()
		if err == nil || (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION)) {
			return err
		}
		if attempt < 9 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return err
}

func fixtureClientBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("OTU_TEST_AUTOPROXY_BINARY")
	if binary == "" {
		t.Skip("set OTU_TEST_AUTOPROXY_BINARY to a client built with -tags=netenvfixture (never use a production binary)")
	}
	return requireFixtureClientBinary(t, binary)
}

func requireFixtureClientBinary(t *testing.T, binary string) string {
	t.Helper()
	// Verify the compile-time adapter switch, not just an environment hint.
	// A normal binary must never run these automatic-proxy acceptance cases.
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal("automatic-proxy fixture provenance unavailable", err)
	}
	fixtureBuild := false
	for _, setting := range info.Settings {
		if setting.Key == "-tags" && setting.Value == "netenvfixture" {
			fixtureBuild = true
		}
	}
	if !fixtureBuild {
		t.Fatal("executable acceptance refuses a binary without fixture-only proxy and ban-marker adapters")
	}
	return binary
}

func waitFixture(t *testing.T, path string, condition func(proxyFixture) bool) proxyFixture {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		f, err := readProxyFixture(path)
		if err == nil && condition(f) {
			return f
		}
		if time.Now().After(deadline) {
			t.Fatal("automatic-proxy fixture transition did not complete", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitFixtureRecoveryComplete(t *testing.T, identityDir string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, activeErr := os.Stat(filepath.Join(identityDir, "snapshot.json"))
		pending, pendingErr := filepath.Glob(filepath.Join(identityDir, "pending-policies", "*.json"))
		if os.IsNotExist(activeErr) && pendingErr == nil && len(pending) == 0 {
			// The guardian releases this handle after its final cleanup. Wait
			// for it rather than racing t.TempDir removal with the helper.
			lease, err := os.OpenFile(filepath.Join(identityDir, "network-settings.lease"), os.O_RDWR, 0600)
			if err == nil {
				lease.Close()
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture recovery did not finish journal cleanup and release ownership")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestFixtureClientAutomaticProxyStartupAndLegacyRecovery(t *testing.T) {
	binary := fixtureClientBinary(t)
	for _, scenario := range []string{"read-only-at-start", "legacy-custom-bypass-handoff", "denied-cleanup-restart", "mandatory-write-denied"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			appData := filepath.Join(dir, "appdata")
			t.Setenv("LOCALAPPDATA", appData)
			fixturePath := filepath.Join(dir, "synthetic-settings.json")
			t.Setenv("OTU_NETENV_FIXTURE", fixturePath)
			store, err := client.NewTokenStore()
			if err != nil {
				t.Fatal(err)
			}
			seedFixtureIdentity(t, store, "automatic-proxy-fixture")
			device, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			pub, err := store.EnsureSSHKey()
			if err != nil {
				t.Fatal(err)
			}
			store.MarkApproved(device.Fingerprint)
			identity := make(map[string][]byte)
			identityDir := filepath.Join(appData, version.ProductName)
			entries, _ := os.ReadDir(identityDir)
			for _, entry := range entries {
				if !entry.IsDir() {
					raw, err := os.ReadFile(filepath.Join(identityDir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					identity[entry.Name()] = raw
				}
			}
			db, err := panel.Open(filepath.Join(dir, "panel.db"), 14)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'autoproxy-fixture','approved',datetime('now'),datetime('now'),?,'autoproxy-fixture')`, device.Token, pub); err != nil {
				t.Fatal(err)
			}
			ph := panel.New(db, panel.NewAuth(db), false).Handler()
			mux := http.NewServeMux()
			mux.Handle("/api/token/", ph)
			mux.Handle("/", server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true}))
			relay := httptest.NewTLSServer(mux)
			defer relay.Close()
			proxyAddr := releaseFreePort(t)
			cfg := fmt.Sprintf("server_addr = %q\nfingerprint = %q\nsocks_addr = \"\"\nhttp_addr = %q\nprofile = \"fast\"\nauto_update = false\nh3_tier = false\nech = false\nfallback_ssh = false\nbypass_list = [\"synthetic.invalid\", \"*.fixture.invalid\"]\n", relay.Listener.Addr().String(), hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw)), proxyAddr)
			cfgPath := filepath.Join(dir, "client.toml")
			if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			original := proxyFixture{Keys: map[string]map[string]fixtureValue{fixtureWinINET: {
				"ProxyEnable":   {Exists: true, Kind: 4, Integer: 0},
				"ProxyServer":   fixtureString("original-proxy.invalid:9000"),
				"ProxyOverride": fixtureString("original-bypass.invalid"),
			}}}
			for _, path := range fixturePolicyPaths {
				original.Keys[path] = map[string]fixtureValue{"ProxyMode": fixtureString("system"), "UnrelatedPolicy": {Exists: true, Kind: 4, Integer: 99}}
			}
			raw, _ := json.Marshal(original)
			f := proxyFixture{}
			_ = json.Unmarshal(raw, &f)
			f.ReadOnlyPolicies = scenario == "read-only-at-start"
			f.DenyMandatoryApply = scenario == "mandatory-write-denied"
			if scenario == "legacy-custom-bypass-handoff" {
				legacyPolicies := make(map[string]any)
				for _, path := range fixturePolicyPaths {
					legacyPolicies[path] = map[string]any{"mode": map[string]any{"exists": true, "data": "system"}, "server": map[string]any{"exists": false}, "bypass": map[string]any{"exists": false}, "had_key": true}
					f.Keys[path]["ProxyServer"] = fixtureString("127.0.0.1:18080")
					f.Keys[path]["ProxyMode"] = fixtureString("fixed_servers")
					f.Keys[path]["ProxyBypassList"] = fixtureString("localhost,127.0.0.1,<local>,synthetic.invalid,*.fixture.invalid")
				}
				f.Keys[fixtureWinINET]["ProxyEnable"] = fixtureValue{Exists: true, Kind: 4, Integer: 1}
				f.Keys[fixtureWinINET]["ProxyServer"] = fixtureString("127.0.0.1:18080")
				f.Keys[fixtureWinINET]["ProxyOverride"] = fixtureString("localhost;127.0.0.1;<local>;synthetic.invalid;*.fixture.invalid")
				legacy := map[string]any{"proxy_enable": 0, "proxy_server": map[string]any{"exists": true, "data": "original-proxy.invalid:9000"}, "proxy_override": map[string]any{"exists": true, "data": "original-bypass.invalid"}, "autoconfig_url": map[string]any{"exists": false}, "policies": legacyPolicies, "otu_applied_server": "127.0.0.1:18080"}
				raw, _ := json.Marshal(legacy)
				if err := privatefile.Write(filepath.Join(identityDir, "snapshot.json"), raw); err != nil {
					t.Fatal(err)
				}
			}
			writeProxyFixture(t, fixturePath, f)
			image := filepath.Join(dir, "otu-client.exe")
			logFile := filepath.Join(dir, "client.log")
			t.Cleanup(func() {
				if t.Failed() {
					log, _ := os.ReadFile(logFile)
					t.Logf("synthetic client log:\n%s", log)
					state, err := readProxyFixture(fixturePath)
					t.Logf("synthetic settings at failure: %+v (read error: %v)", state, err)
				}
			})
			var child *os.Process
			if scenario == "legacy-custom-bypass-handoff" {
				launcherData, err := os.ReadFile(os.Args[0])
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(image, launcherData, 0700); err != nil {
					t.Fatal(err)
				}
				pidFile := filepath.Join(dir, "child.pid")
				parent := exec.Command(image, "-test.run=^TestLegacyReleaseLauncherChild$")
				parent.Env = append(os.Environ(), "OTU_LEGACY_RELEASE_LAUNCHER=1", "OTU_TEST_RELEASE_CLIENT="+binary, "OTU_TEST_RELEASE_CONFIG="+cfgPath, "OTU_TEST_RELEASE_PID="+pidFile, "OTU_TEST_RELEASE_LOG="+logFile, "OTU_TEST_RELEASE_AUTOPROXY=1", "OTU_TEST_LEGACY_HINT=1")
				if err := parent.Run(); err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(pidFile)
				if err != nil {
					t.Fatal(err)
				}
				var pid int
				if _, err := fmt.Sscan(string(raw), &pid); err != nil {
					t.Fatal(err)
				}
				child, err = os.FindProcess(pid)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				data, err := os.ReadFile(binary)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(image, data, 0700); err != nil {
					t.Fatal(err)
				}
				log, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(image, "-c", cfgPath, "--auto-proxy")
				cmd.Env, cmd.Stdout, cmd.Stderr = os.Environ(), log, log
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				_ = log.Close()
				child = cmd.Process
				if scenario == "mandatory-write-denied" {
					done := make(chan error, 1)
					go func() { done <- cmd.Wait() }()
					select {
					case <-done:
					case <-time.After(20 * time.Second):
						_ = child.Kill()
						<-done
						t.Fatal("mandatory-denied client remained ready")
					}
					waitFixture(t, fixturePath, func(f proxyFixture) bool { return reflect.DeepEqual(f.Keys, original.Keys) })
					waitFixtureRecoveryComplete(t, identityDir)
					logs, _ := os.ReadFile(logFile)
					if !strings.Contains(string(logs), "synthetic mandatory write denied") || strings.Contains(string(logs), "System proxy set to") {
						t.Fatal("mandatory failure was hidden or reported as ready", string(logs))
					}
					return
				}
			}
			defer func() { _ = child.Kill(); _, _ = child.Wait(); _ = child.Release() }()
			applied := waitFixture(t, fixturePath, func(f proxyFixture) bool {
				if f.Keys[fixtureWinINET]["ProxyServer"].Text != proxyAddr || f.Keys[fixtureWinINET]["ProxyEnable"].Integer != 1 {
					return false
				}
				for _, path := range fixturePolicyPaths {
					if scenario != "read-only-at-start" && (f.Keys[path]["ProxyServer"].Text != proxyAddr || f.Keys[path]["ProxyMode"].Text != "fixed_servers") {
						return false
					}
				}
				return true
			})
			readyDeadline := time.Now().Add(10 * time.Second)
			for {
				logs, _ := os.ReadFile(logFile)
				if strings.Contains(string(logs), "System proxy set to") {
					break
				}
				if time.Now().After(readyDeadline) {
					t.Fatal("automatic-proxy startup exited before announcing completed settings initialization", string(logs))
				}
				time.Sleep(50 * time.Millisecond)
			}
			bulk := bytes.Repeat([]byte("automatic-proxy-fixture"), 1<<17)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bulk) }))
			defer origin.Close()
			proxyURL, err := url.Parse("http://" + applied.Keys[fixtureWinINET]["ProxyServer"].Text)
			if err != nil {
				t.Fatal(err)
			}
			// Follow the proxy address configured in the synthetic WinINET
			// bundle, not a separately hard-coded manual proxy connection.
			hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			defer hc.CloseIdleConnections()
			_, originPort, _ := net.SplitHostPort(origin.Listener.Addr().String())
			resp, err := hc.Get("http://localhost:" + originPort + "/")
			if err != nil {
				t.Fatal("automatic-proxy client startup did not remain functional", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(body, bulk) {
				t.Fatal("automatic-proxy fixture lost bulk payload", err)
			}
			policy, err := db.AccessPolicy(device.Token)
			if err != nil || policy.UsedBytes < int64(len(bulk)) {
				t.Fatal("automatic-proxy fixture bypassed authentication/accounting", err)
			}
			if scenario == "denied-cleanup-restart" {
				f, err := readProxyFixture(fixturePath)
				if err != nil {
					t.Fatal(err)
				}
				f.DenyPolicyRestore = true
				writeProxyFixture(t, fixturePath, f)
			}
			if err := child.Kill(); err != nil {
				t.Fatal(err)
			}
			_, _ = child.Wait()
			waitFixture(t, fixturePath, func(f proxyFixture) bool {
				return reflect.DeepEqual(f.Keys[fixtureWinINET], original.Keys[fixtureWinINET])
			})
			if scenario == "denied-cleanup-restart" {
				pendingDir := filepath.Join(identityDir, "pending-policies")
				deadline := time.Now().Add(10 * time.Second)
				for {
					pending, _ := filepath.Glob(filepath.Join(pendingDir, "*.json"))
					_, activeErr := os.Stat(filepath.Join(identityDir, "snapshot.json"))
					if len(pending) != 0 && os.IsNotExist(activeErr) {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("denied cleanup did not detach recovery evidence")
					}
					time.Sleep(50 * time.Millisecond)
				}
				f, err := readProxyFixture(fixturePath)
				if err != nil {
					t.Fatal(err)
				}
				f.DenyPolicyRestore = false
				writeProxyFixture(t, fixturePath, f)
				// A bounded guardian may briefly hold the lease between this
				// fixture write and the separate --restore invocation.
				retryDeadline := time.Now().Add(10 * time.Second)
				for {
					restore := exec.Command(image, "-c", cfgPath, "--restore")
					restore.Env = os.Environ()
					out, err := restore.CombinedOutput()
					if err == nil {
						break
					}
					if !strings.Contains(string(out), "another client owns the settings lease") || time.Now().After(retryDeadline) {
						t.Fatal("new-process pending cleanup retry failed", err, string(out))
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
			waitFixture(t, fixturePath, func(f proxyFixture) bool { return reflect.DeepEqual(f.Keys, original.Keys) })
			waitFixtureRecoveryComplete(t, identityDir)
			for name, before := range identity {
				after, err := os.ReadFile(filepath.Join(identityDir, name))
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("automatic-proxy handoff modified synthetic identity file %s: %v", name, err)
				}
			}
			cfgAfter, err := os.ReadFile(cfgPath)
			if err != nil || !bytes.Equal(cfgAfter, []byte(cfg)) {
				t.Fatal("automatic-proxy handoff modified synthetic configuration", err)
			}
			logs, _ := os.ReadFile(logFile)
			if scenario == "read-only-at-start" && !strings.Contains(string(logs), "browser-policy bundles were skipped") {
				t.Fatal("read-only startup did not expose a nonfatal browser warning")
			}
			t.Logf("%s: actual --auto-proxy startup, %d authenticated payload bytes and fixture-only journal recovery passed; HKCU unavailable in this build", scenario, len(bulk))
		})
	}
}

func TestProductionClientVersionPreflightIsStateFree(t *testing.T) {
	binary := os.Getenv("OTU_TEST_PRODUCTION_CLIENT_BINARY")
	if binary == "" {
		t.Skip("set OTU_TEST_PRODUCTION_CLIENT_BINARY to a normal staged client; only --version is executed")
	}
	dir := t.TempDir()
	stateDir := filepath.Join(dir, version.ProductName)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stateDir, "snapshot.json")
	if err := os.WriteFile(marker, []byte("synthetic corrupt marker"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "--version")
	cmd.Env = append(os.Environ(), "LOCALAPPDATA="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("opentunnel client")) {
		t.Fatal("production version preflight failed", err, string(out))
	}
	raw, err := os.ReadFile(marker)
	if err != nil || !bytes.Equal(raw, []byte("synthetic corrupt marker")) {
		t.Fatal("production version preflight touched recovery state", err)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil || len(entries) != 1 {
		t.Fatal("production version preflight opened identity or crash-log state", err)
	}
}
