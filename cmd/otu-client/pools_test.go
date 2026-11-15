package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/serverpool"
)

func commandPool(t *testing.T) serverpool.Profile {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	p := serverpool.Profile{Name: "Synthetic command operator", AuthorityID: strings.Repeat("a", 64), IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ApprovalRequired: true, Nodes: []serverpool.Node{{ID: "entry", Name: "Entry", Address: "entry.example:443", Pins: []string{strings.Repeat("b", 64)}, WSPath: "/stream"}}}
	if err := p.Sign(key, now); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPoolCLIImportDoesNotSelectOrMintDeviceAndRefusesFlagMixing(t *testing.T) {
	app := t.TempDir()
	t.Setenv("LOCALAPPDATA", app)
	p := commandPool(t)
	path := filepath.Join(t.TempDir(), "synthetic-profile.json")
	if err := serverpool.Export(path, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	if handled, err := handlePoolCommands([]string{"--pool-import", path, "--accept-pool", strings.Repeat("f", 64)}); !handled || err == nil {
		t.Fatal("mismatched consent accepted")
	}
	if handled, err := handlePoolCommands([]string{"--pool-import", path, "--accept-pool", p.ID}); !handled || err != nil {
		t.Fatal(err)
	}
	root, _ := client.NewTokenStore()
	store := serverpool.Store{Dir: root.Dir}
	if selected, _ := store.Selected(); selected != "default" {
		t.Fatal("import selected different operator")
	}
	for _, name := range []string{"device.json", "device_ssh", "snapshot.json", "crash.log"} {
		if _, err := os.Stat(filepath.Join(root.Dir, name)); !os.IsNotExist(err) {
			t.Fatal("profile command opened runtime state", name)
		}
	}
	if handled, err := handlePoolCommands([]string{"--pool-list", "--auto-proxy"}); !handled || err == nil {
		t.Fatal("profile command accepted network mutation flag")
	}
	if handled, err := handlePoolCommands([]string{"--pool-select", p.ID}); !handled || err != nil {
		t.Fatal(err)
	}
	if selected, _ := store.Selected(); selected != p.ID {
		t.Fatal("selection not persisted")
	}
	if handled, err := handlePoolCommands([]string{"--pool-list"}); !handled || err != nil {
		t.Fatal(err)
	}
}

func TestTrustedPoolKeepsOnlyLocalSettingsAndDefaultConfigIsUnchanged(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	p := commandPool(t)
	selector, err := client.NewPoolSelector(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.ClientConf{ServerAddr: "default.example:443", Token: "synthetic-default-secret", SSHKey: "user-key", SSHHostKeys: "default-pins", SSHDialHostOverride: "default-ssh.example", CarrierSOCKS: "127.0.0.1:19090", CarrierTarget: "127.0.0.1:8082", Reality: &config.RealityClient{Enabled: true}, InnerTLSPins: []string{strings.Repeat("c", 64)}, Insecure: true, AllowUntrustedBootstrap: true, ServerFallbacks: []string{"fallback.example"}, Profile: "balanced", SOCKSAddr: "127.0.0.1:18000", HTTPAddr: "127.0.0.1:18001", BypassList: []string{"local"}, AutoUpdate: boolPtr(false)}
	configureTrustedPool(cfg, selector)
	if cfg.Token != "" || cfg.SSHKey != "" || cfg.SSHHostKeys != "" || cfg.SSHDialHostOverride != "" || cfg.CarrierSOCKS != "" || cfg.Reality != nil || cfg.Insecure || cfg.AllowUntrustedBootstrap || cfg.H3TierEnabled() || cfg.FallbackSSHEnabled() || cfg.ECHEnabled() || len(cfg.ServerFallbacks) > 0 || len(cfg.InnerTLSPins) > 0 {
		t.Fatal("default operator credentials/trust fell through to imported pool")
	}
	if cfg.SOCKSAddr != "127.0.0.1:18000" || cfg.HTTPAddr != "127.0.0.1:18001" || cfg.Profile != "balanced" || cfg.AutoUpdateEnabled() {
		t.Fatal("local application settings lost")
	}
	defaultCfg := &config.ClientConf{ServerAddr: "default.example:443", SSHKey: "custom-user-key", Token: "synthetic-default"}
	if selector, err := selectedPool(defaultCfg, "default"); err != nil || selector != nil || defaultCfg.Token != "synthetic-default" || defaultCfg.SSHKey != "custom-user-key" {
		t.Fatal("default compatibility changed", err)
	}
}
