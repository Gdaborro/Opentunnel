package config

import (
	"path/filepath"
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
	if c.ServerAddr == "" || c.Token == "" || c.Fingerprint == "" {
		t.Fatalf("default config incomplete: %+v", c)
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
