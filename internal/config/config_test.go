package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteDefaultClientConfigRoundtrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.toml")
	if err := WriteDefaultClientConfig(p); err != nil {
		t.Fatal(err)
	}
	c, err := LoadClient(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerAddr == "" || c.Fingerprint == "" {
		t.Fatalf("default config incomplete: %+v", c)
	}
	if c.Token != "" {
		t.Fatal("default config must NOT embed a shared token (per-device auth)")
	}
	if !c.FallbackSSHEnabled() {
		t.Fatal("default config should enable fallback_ssh")
	}
	if c.SSHKey != "tun.key" {
		t.Fatalf("default ssh_key = %q, want relative tun.key", c.SSHKey)
	}
	if !c.MuxEnabled() || !c.UDPEnabled() {
		t.Fatal("default config should enable mux and udp")
	}
}

func TestAllowHostileSSHDefaultsOn(t *testing.T) {
	c := &ClientConf{}
	if !c.AllowHostileSSH() {
		t.Fatal("hostile SSH must default to allowed (connectivity first)")
	}
	off := false
	c.HostileSSH = &off
	if c.AllowHostileSSH() {
		t.Fatal("explicit false must forbid hostile SSH")
	}
}

func TestDefaultPathsAreBoring(t *testing.T) {
	if strings.Contains(DefaultClientTOML, "ws_path = \"/ws\"") {
		t.Fatal("default client config must not use the /ws path")
	}
	p := filepath.Join(t.TempDir(), "client.toml")
	if err := WriteDefaultClientConfig(p); err != nil {
		t.Fatal(err)
	}
	c, err := LoadClient(p)
	if err != nil {
		t.Fatalf("default config must load: %v", err)
	}
	if c.WSPath == "/ws" || c.WSPath == "" {
		t.Fatalf("default ws_path must be boring, got %q", c.WSPath)
	}
	if !c.AllowHostileSSH() {
		t.Fatal("default config must allow hostile SSH (connectivity first)")
	}
}
