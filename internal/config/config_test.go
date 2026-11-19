package config

import (
	"path/filepath"
	"strings"
	"testing"

	"opentunnel/internal/version"
)

func TestWriteDefaultClientConfigRoundtrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "client.toml")
	if err := WriteDefaultClientConfig(p); err != nil {
		t.Fatal(err)
	}
	c, err := LoadClient(p)
	if version.RequiresOwnServerConfiguration {
		if err == nil {
			t.Fatal("generic first-run template connected without operator configuration")
		}
		if strings.Contains(DefaultClientTOML, "aborro.dev") || strings.Contains(DefaultClientTOML, "CHANGE_ME_LONG_RANDOM_SECRET") {
			t.Fatal("generic client embeds hosted routing or a shared credential template")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerAddr == "" || c.Fingerprint == "" {
		t.Fatalf("default config incomplete: %+v", c)
	}
	if pins := c.FingerprintSet(); len(pins) != 1 || pins[0] != "20687078735870a4c74ea153d8ea81115b4478d8da921a3beeeef6ffbc77a322" {
		t.Fatalf("hosted default pins differ from the independently verified 2026-11-19 public leaf: %q", pins)
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

func TestDialHostPortAndSNI(t *testing.T) {
	c := &ClientConf{ServerAddr: "cdn.aborro.dev:443"}
	if got := c.DialHostPort(); got != "cdn.aborro.dev:443" {
		t.Fatalf("default dial=%q", got)
	}
	if got := c.SNIHost(); got != "cdn.aborro.dev" {
		t.Fatalf("sni=%q", got)
	}
	c.ServerIP = "203.0.113.23"
	if got := c.DialHostPort(); got != "203.0.113.23:443" {
		t.Fatalf("IP literal dial=%q", got)
	}
	if got := c.SNIHost(); got != "cdn.aborro.dev" {
		t.Fatalf("SNI must stay the hostname, got %q", got)
	}
	c.ServerAddr = "example.com" // no port -> 443 default
	c.ServerIP = "9.9.9.9"
	if got := c.DialHostPort(); got != "9.9.9.9:443" {
		t.Fatalf("port default dial=%q", got)
	}
	c.SSHUser = "tun"
	if got := c.SSHDialHost(); got != "9.9.9.9" {
		t.Fatalf("ssh must follow the literal, got %q", got)
	}
	c.ServerIP = ""
	c.ServerAddr = "cdn.aborro.dev:443"
	c.SSHKey = "k"
	if got := c.SSHDialHost(); got != "cdn.aborro.dev" {
		t.Fatalf("ssh default host=%q", got)
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
	if version.RequiresOwnServerConfiguration {
		if err == nil || !strings.Contains(DefaultClientTOML, `ws_path = "/api/v1/stream"`) {
			t.Fatal("generic template has an implicit server or unexpected protocol path")
		}
		return
	}
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
