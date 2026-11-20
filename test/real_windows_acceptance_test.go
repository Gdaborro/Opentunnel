//go:build windows && !netenvfixture

package test

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/hex"
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
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

type realRegistryValue struct {
	Exists  bool
	Kind    uint32
	Text    string
	Integer uint64
}

type realClientProcess struct {
	cmd *exec.Cmd
	log *os.File
}

func requireRealWindowsRunner(t *testing.T) {
	t.Helper()
	if os.Getenv("OTU_REAL_WINDOWS_ACCEPTANCE") != "disposable-runner" || os.Getenv("CI") != "true" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Skip("real registry acceptance requires an explicitly flagged disposable GitHub Windows runner")
	}
}

func realWindowsClient(t *testing.T) string {
	t.Helper()
	requireRealWindowsRunner(t)
	binary := os.Getenv("OTU_REAL_WINDOWS_CLIENT")
	if binary == "" {
		t.Fatal("OTU_REAL_WINDOWS_CLIENT must name the exact non-fixture candidate")
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal("real candidate buildinfo unavailable", err)
	}
	for _, setting := range info.Settings {
		if setting.Key == "-tags" && strings.Contains(setting.Value, "netenvfixture") {
			t.Fatal("real registry acceptance refuses the compile-time fixture adapter")
		}
	}
	if os.Getenv("OTU_NETENV_FIXTURE") != "" {
		t.Fatal("fixture path must not be present in real registry acceptance")
	}
	return binary
}

func readRealRegistryValue(path, name string) (realRegistryValue, error) {
	value := realRegistryValue{}
	key, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	defer key.Close()
	size, kind, err := key.GetValue(name, nil)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return value, nil
	}
	if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
		return value, err
	}
	if size > 64<<10 {
		return value, errors.New("real registry value exceeds acceptance bound")
	}
	value.Exists, value.Kind = true, kind
	switch kind {
	case registry.SZ, registry.EXPAND_SZ:
		value.Text, _, err = key.GetStringValue(name)
	case registry.DWORD, registry.QWORD:
		value.Integer, _, err = key.GetIntegerValue(name)
	default:
		err = fmt.Errorf("unexpected real registry type %d at %s\\%s", kind, path, name)
	}
	return value, err
}

func realRegistrySnapshot(t *testing.T) map[string]map[string]realRegistryValue {
	t.Helper()
	requireRealWindowsRunner(t)
	snapshot := map[string]map[string]realRegistryValue{fixtureWinINET: {}}
	for _, name := range []string{"ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"} {
		value, err := readRealRegistryValue(fixtureWinINET, name)
		if err != nil {
			t.Fatal("read real WinINET state", err)
		}
		snapshot[fixtureWinINET][name] = value
	}
	for _, path := range fixturePolicyPaths {
		snapshot[path] = map[string]realRegistryValue{}
		for _, name := range []string{"ProxyMode", "ProxyServer", "ProxyBypassList"} {
			value, err := readRealRegistryValue(path, name)
			if err != nil {
				t.Fatal("read real browser-policy state", err)
			}
			snapshot[path][name] = value
		}
	}
	return snapshot
}

func writeRealRegistryValue(path, name string, value realRegistryValue) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if !value.Exists {
		err := key.DeleteValue(name)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return err
	}
	switch value.Kind {
	case registry.SZ:
		return key.SetStringValue(name, value.Text)
	case registry.EXPAND_SZ:
		return key.SetExpandStringValue(name, value.Text)
	case registry.DWORD:
		return key.SetDWordValue(name, uint32(value.Integer))
	case registry.QWORD:
		return key.SetQWordValue(name, value.Integer)
	default:
		return errors.New("unsupported real registry restoration type")
	}
}

func restoreRealRegistry(t *testing.T, snapshot map[string]map[string]realRegistryValue) {
	t.Helper()
	if os.Getenv("OTU_REAL_WINDOWS_ACCEPTANCE") != "disposable-runner" || os.Getenv("CI") != "true" || os.Getenv("RUNNER_OS") != "Windows" {
		return
	}
	for path, values := range snapshot {
		for name, value := range values {
			if err := writeRealRegistryValue(path, name, value); err != nil {
				t.Errorf("restore real registry %s\\%s: %v", path, name, err)
			}
		}
	}
}

func waitRealRegistry(t *testing.T, expected map[string]map[string]realRegistryValue) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		actual := realRegistrySnapshot(t)
		if reflect.DeepEqual(actual, expected) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("real registry did not return to its exact original values\nwant: %+v\ngot:  %+v", expected, actual)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitRealProxy(t *testing.T, proxyAddr string) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for {
		server, err := readRealRegistryValue(fixtureWinINET, "ProxyServer")
		if err == nil && server.Exists && server.Text == proxyAddr {
			enabled, err := readRealRegistryValue(fixtureWinINET, "ProxyEnable")
			if err == nil && enabled.Exists && enabled.Integer == 1 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("real client did not apply the journaled system proxy", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func realAcceptanceConfig(t *testing.T, scenario string) (binary, config, proxyAddr string, db *panel.DB) {
	t.Helper()
	candidate := realWindowsClient(t)
	image, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	binary = filepath.Join(t.TempDir(), "otu-client.exe")
	if err := os.WriteFile(binary, image, 0o700); err != nil {
		t.Fatal(err)
	}
	appData := filepath.Join(t.TempDir(), "appdata")
	t.Setenv("LOCALAPPDATA", appData)
	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	seedFixtureIdentity(t, store, scenario)
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	store.MarkApproved(device.Fingerprint)
	dir := t.TempDir()
	db, err = panel.Open(filepath.Join(dir, "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,?,'approved',datetime('now'),datetime('now'),?,'real-windows-acceptance')`, device.Token, scenario, pub); err != nil {
		t.Fatal(err)
	}
	panelHandler := panel.New(db, panel.NewAuth(db), false).Handler()
	mux := http.NewServeMux()
	mux.Handle("/api/token/", panelHandler)
	mux.Handle("/", server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true}))
	relay := httptest.NewTLSServer(mux)
	t.Cleanup(relay.Close)
	proxyAddr = releaseFreePort(t)
	config = fmt.Sprintf("server_addr = %q\nfingerprint = %q\nsocks_addr = \"\"\nhttp_addr = %q\nprofile = \"fast\"\nauto_update = false\nh3_tier = false\nech = false\nfallback_ssh = false\nbypass_list = [\"synthetic.invalid\"]\n", relay.Listener.Addr().String(), hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw)), proxyAddr)
	configPath := filepath.Join(dir, "client.toml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return binary, configPath, proxyAddr, db
}

func startRealClient(t *testing.T, binary, config string) *realClientProcess {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "client.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-c", config, "--auto-proxy")
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	process := &realClientProcess{cmd: cmd, log: log}
	t.Cleanup(func() {
		_ = process.cmd.Process.Kill()
		_, _ = process.cmd.Process.Wait()
		_ = process.log.Close()
		t.Logf("real client log %s:\n%s", logPath, mustReadAcceptanceLog(logPath))
	})
	return process
}

func mustReadAcceptanceLog(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	return string(raw)
}

func (p *realClientProcess) wait(t *testing.T) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		_ = p.log.Close()
		return err
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
		_ = p.log.Close()
		t.Fatal("real client did not stop within the acceptance deadline")
		return nil
	}
}

func verifyRealClientTransfer(t *testing.T, process *realClientProcess, proxyAddr string, db *panel.DB) {
	t.Helper()
	waitRealProxy(t, proxyAddr)
	bulk := bytes.Repeat([]byte("real-windows-acceptance"), 1<<16)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bulk) }))
	defer origin.Close()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer httpClient.CloseIdleConnections()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:"+port+"/", nil)
	response, err := httpClient.Do(req)
	if err != nil {
		t.Fatal("real authenticated proxy transfer failed", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(body, bulk) {
		t.Fatalf("real proxy payload mismatch: got=%d want=%d err=%v", len(body), len(bulk), err)
	}
	var used int64
	if err := db.QueryRow(`SELECT bytes_up+bytes_down FROM peers`).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used < int64(len(bulk)) {
		t.Fatalf("real authenticated payload was not accounted: used=%d payload=%d", used, len(bulk))
	}
}

func TestRealWindowsProxyGracefulAndForcedRecovery(t *testing.T) {
	_ = realWindowsClient(t)
	original := realRegistrySnapshot(t)
	defer restoreRealRegistry(t, original)
	binary, config, proxyAddr, db := realAcceptanceConfig(t, "real-windows-graceful")
	process := startRealClient(t, binary, config)
	verifyRealClientTransfer(t, process, proxyAddr, db)
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(process.cmd.Process.Pid)); err != nil {
		t.Fatal("deliver graceful Ctrl+Break", err)
	}
	if err := process.wait(t); err != nil {
		t.Logf("graceful client exit status: %v", err)
	}
	waitRealRegistry(t, original)

	forced := startRealClient(t, binary, config)
	verifyRealClientTransfer(t, forced, proxyAddr, db)
	if err := forced.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = forced.wait(t)
	waitRealRegistry(t, original)
	waitFixtureRecoveryComplete(t, filepath.Join(os.Getenv("LOCALAPPDATA"), version.NetworkStateName()))
}

func TestRealWindowsProxyCompetingChangeIsNotOverwritten(t *testing.T) {
	_ = realWindowsClient(t)
	original := realRegistrySnapshot(t)
	defer restoreRealRegistry(t, original)
	binary, config, proxyAddr, db := realAcceptanceConfig(t, "real-windows-competing")
	process := startRealClient(t, binary, config)
	verifyRealClientTransfer(t, process, proxyAddr, db)
	competing := realRegistryValue{Exists: true, Kind: registry.SZ, Text: "competing.invalid:9001"}
	if err := writeRealRegistryValue(fixtureWinINET, "ProxyServer", competing); err != nil {
		t.Fatal(err)
	}
	if err := process.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = process.wait(t)
	time.Sleep(6 * time.Second)
	current, err := readRealRegistryValue(fixtureWinINET, "ProxyServer")
	if err != nil || current.Text != competing.Text {
		t.Fatalf("guardian overwrote a competing proxy value: %+v, %v", current, err)
	}
	journal := filepath.Join(os.Getenv("LOCALAPPDATA"), version.NetworkStateName(), "snapshot.json")
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("competing-change recovery evidence was discarded", err)
	}
	restoreRealRegistry(t, original)
}

func TestRealWindowsProxyReadOnlyACLDoesNotPartiallyApply(t *testing.T) {
	_ = realWindowsClient(t)
	original := realRegistrySnapshot(t)
	defer restoreRealRegistry(t, original)
	binary, config, _, _ := realAcceptanceConfig(t, "real-windows-acl")
	backup := filepath.Join(t.TempDir(), "acl.sddl")
	setReadOnly := `Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; $p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $a=Get-Acl $p; $a.GetSecurityDescriptorSddlForm('All') | Set-Content -LiteralPath $env:OTU_ACL_BACKUP -Encoding ascii; $a.SetAccessRuleProtection($true,$false); $u=[Security.Principal.WindowsIdentity]::GetCurrent().Name; $r=New-Object Security.AccessControl.RegistryAccessRule($u,'ReadKey','Allow'); $a.AddAccessRule($r); Set-Acl $p $a`
	restoreACL := `Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; $p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; $a=Get-Acl $p; $a.SetSecurityDescriptorSddlForm((Get-Content -LiteralPath $env:OTU_ACL_BACKUP -Raw),'All'); Set-Acl $p $a`
	t.Setenv("OTU_ACL_BACKUP", backup)
	if output, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-Command", setReadOnly).CombinedOutput(); err != nil {
		t.Fatal("apply disposable registry ACL", err, string(output))
	}
	defer func() {
		if output, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-Command", restoreACL).CombinedOutput(); err != nil {
			t.Errorf("restore disposable registry ACL: %v: %s", err, output)
		}
	}()
	process := startRealClient(t, binary, config)
	_ = process.wait(t)
	waitRealRegistry(t, original)
	if output, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-Command", restoreACL).CombinedOutput(); err != nil {
		t.Fatal("restore registry ACL before explicit recovery", err, string(output))
	}
	restore := exec.Command(binary, "-c", config, "--restore")
	restore.Env = os.Environ()
	if output, err := restore.CombinedOutput(); err != nil {
		t.Fatal("explicit real-registry recovery after ACL restore failed", err, string(output))
	}
	waitRealRegistry(t, original)
}
