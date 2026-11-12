//go:build windows

package test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// A copied test executable emulates the legacy updater's running .old image.
// This never runs an old production client or touches its actual registry,
// config, private identity, update feed or installed executable.
func TestLegacyReleaseLauncherChild(t *testing.T) {
	if os.Getenv("OTU_LEGACY_RELEASE_LAUNCHER") != "1" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		os.Exit(51)
	}
	if err := os.Rename(exe, exe+".old"); err != nil {
		os.Exit(52)
	}
	data, err := os.ReadFile(os.Getenv("OTU_TEST_RELEASE_CLIENT"))
	if err != nil {
		os.Exit(53)
	}
	if err := os.WriteFile(exe, data, 0700); err != nil {
		os.Exit(54)
	}
	cmd := exec.Command(exe, "-c", os.Getenv("OTU_TEST_RELEASE_CONFIG"))
	cmd.Env = append(os.Environ(), "OTU_UPDATE_PARENT_PID=")
	if os.Getenv("OTU_TEST_LEGACY_HINT") == "1" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("OTU_UPDATE_PARENT_PID=%d", os.Getpid()))
	}
	log, err := os.OpenFile(os.Getenv("OTU_TEST_RELEASE_LOG"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		os.Exit(55)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		os.Exit(56)
	}
	if err := os.WriteFile(os.Getenv("OTU_TEST_RELEASE_PID"), []byte(fmt.Sprint(cmd.Process.Pid)), 0600); err != nil {
		os.Exit(57)
	}
	// Ensure the replacement encounters an alive updater on both historical
	// paths: environment hint (v1.1.5) and same-image .old detection (older).
	time.Sleep(750 * time.Millisecond)
	os.Exit(0)
}

func releaseFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestActualReleaseClientStartupAndLegacyUpgradeHandoff(t *testing.T) {
	binary := os.Getenv("OTU_TEST_CLIENT_BINARY")
	if binary == "" {
		t.Skip("set OTU_TEST_CLIENT_BINARY to a staged release executable")
	}
	for _, hint := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent_hint_%t", hint), func(t *testing.T) {
			dir := t.TempDir()
			appData := filepath.Join(dir, "appdata")
			t.Setenv("LOCALAPPDATA", appData)
			store, err := client.NewTokenStore()
			if err != nil {
				t.Fatal(err)
			}
			device, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			pub, err := store.EnsureSSHKey()
			if err != nil {
				t.Fatal(err)
			}
			store.MarkApproved(device.Fingerprint)
			db, err := panel.Open(filepath.Join(dir, "panel.db"), 14)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'release-fixture','approved',datetime('now'),datetime('now'),?,'release-fixture')`, device.Token, pub); err != nil {
				t.Fatal(err)
			}
			ph := panel.New(db, panel.NewAuth(db), false).Handler()
			relayMux := http.NewServeMux()
			relayMux.Handle("/api/token/", ph)
			relayMux.Handle("/", server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true}))
			relay := httptest.NewTLSServer(relayMux)
			defer relay.Close()
			proxyAddr := releaseFreePort(t)
			config := fmt.Sprintf("server_addr = %q\nfingerprint = %q\nsocks_addr = %q\nhttp_addr = \"\"\nprofile = \"fast\"\nauto_update = false\nh3_tier = false\nech = false\nfallback_ssh = false\n", relay.Listener.Addr().String(), hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw)), proxyAddr)
			cfgPath := filepath.Join(dir, "client.toml")
			if err := os.WriteFile(cfgPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			launcher := filepath.Join(dir, "fixture-client.exe")
			data, err := os.ReadFile(os.Args[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(launcher, data, 0700); err != nil {
				t.Fatal(err)
			}
			pidFile, logFile := filepath.Join(dir, "child.pid"), filepath.Join(dir, "client.log")
			parent := exec.Command(launcher, "-test.run=^TestLegacyReleaseLauncherChild$")
			parent.Env = append(os.Environ(), "OTU_LEGACY_RELEASE_LAUNCHER=1", "OTU_TEST_RELEASE_CLIENT="+binary, "OTU_TEST_RELEASE_CONFIG="+cfgPath, "OTU_TEST_RELEASE_PID="+pidFile, "OTU_TEST_RELEASE_LOG="+logFile)
			if hint {
				parent.Env = append(parent.Env, "OTU_TEST_LEGACY_HINT=1")
			}
			if err := parent.Run(); err != nil {
				t.Fatal("legacy launcher failed", err)
			}
			pidRaw, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			var pid int
			if _, err := fmt.Sscan(string(pidRaw), &pid); err != nil {
				t.Fatal(err)
			}
			child, err := os.FindProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = child.Kill(); _, _ = child.Wait(); _ = child.Release() }()
			deadline := time.Now().Add(20 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
				if err == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("actual replacement did not establish local proxy")
				}
				time.Sleep(50 * time.Millisecond)
			}
			bulk := bytes.Repeat([]byte("actual-release-client"), 1<<17)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bulk) }))
			defer origin.Close()
			dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			cd := dialer.(proxy.ContextDialer)
			hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: cd.DialContext}}
			defer hc.CloseIdleConnections()
			// The client's loop guard bypasses the relay host 127.0.0.1. Use a
			// different local authority so this fixture really traverses the tunnel.
			_, originPort, _ := net.SplitHostPort(origin.Listener.Addr().String())
			resp, err := hc.Get("http://localhost:" + originPort + "/")
			if err != nil {
				t.Fatal("actual release proxy request failed", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(body, bulk) {
				t.Fatal("actual release proxy lost payload", err)
			}
			policy, err := db.AccessPolicy(device.Token)
			if err != nil || policy.UsedBytes < int64(len(bulk)) {
				t.Fatal("release fixture bypassed authenticated relay/accounting", err)
			}
			t.Logf("actual client legacy handoff (parent hint=%t), preserved synthetic identity and %d payload bytes passed; no system proxy mutation", hint, len(bulk))
		})
	}
}
