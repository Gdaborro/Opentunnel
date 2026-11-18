//go:build genericclient

package config

import (
	"strings"
	"testing"
)

func TestGenericClientRequiresOwnEndpointAndVerifiedPublicPins(t *testing.T) {
	for _, raw := range []string{
		`server_addr = ""`,
		`server_addr = "synthetic.invalid:443"`,
		"server_addr = \"synthetic.invalid:443\"\nfingerprint = \"not-a-public-pin\"\n",
		"server_addr = \"synthetic.invalid:443\"\nfingerprint = \"" + strings.Repeat("a", 64) + "\"\ninsecure = true\n",
		"server_addr = \"synthetic.invalid:443\"\nfingerprint = \"" + strings.Repeat("a", 64) + "\"\nallow_untrusted_bootstrap = true\n",
	} {
		if _, err := LoadClient(configFixture(t, raw)); err == nil {
			t.Fatal("incomplete/unverified generic setup accepted")
		}
	}
	if _, err := LoadClient(configFixture(t, "server_addr = \"synthetic.invalid:443\"\nfingerprint = \""+strings.Repeat("a", 64)+"\"\n")); err != nil {
		t.Fatal("explicit self-hosted verified setup refused", err)
	}
}
