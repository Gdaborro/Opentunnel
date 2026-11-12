package config

import (
	"os"
	"path/filepath"
	"testing"
)

func configFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestInternalListenersRequireLiteralLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8081", "localhost:8081", "203.0.113.1:8081", "[::]:8081", "127.0.0.1:0"} {
		if _, err := LoadServer(configFixture(t, "listen_internal = \""+addr+"\"\n")); err == nil {
			t.Fatalf("unsafe internal listener accepted: %s", addr)
		}
	}
	if _, err := LoadServer(configFixture(t, "listen_internal = \"127.0.0.1:8081\"\n")); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedEnforcementDateFailsConfiguration(t *testing.T) {
	if _, err := LoadServer(configFixture(t, "require_v5_after = \"not-a-date\"\n")); err == nil {
		t.Fatal("invalid enforcement date silently disabled v5 policy")
	}
}
func TestClientExposureAndCarrierLoopsRequireExplicitChoice(t *testing.T) {
	base := "server_addr = \"example.test:443\"\n"
	for _, extra := range []string{"socks_addr = \"0.0.0.0:1080\"\n", "carrier_socks = \"203.0.113.1:19090\"\n", "carrier_socks = \"127.0.0.1:1080\"\n", "transport = \"unknown\"\n"} {
		if _, err := LoadClient(configFixture(t, base+extra)); err == nil {
			t.Fatalf("unsafe config accepted: %s", extra)
		}
	}
	if _, err := LoadClient(configFixture(t, base+"socks_addr = \"0.0.0.0:1080\"\nallow_non_loopback_proxy = true\n")); err != nil {
		t.Fatal(err)
	}
}
