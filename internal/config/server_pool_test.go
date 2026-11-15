package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPoolServerConfigRefusesLegacyOrAutomaticAdmission(t *testing.T) {
	base := fmt.Sprintf("pool_id = %q\nenrollment_login = true\n", strings.Repeat("a", 64))
	for _, tc := range []struct {
		name, extra string
		valid       bool
	}{
		{"manual", "", true},
		{"automatic approval", "auto_approve = true\n", false},
		{"static token", "static_token_only = true\ntoken = \"synthetic-legacy-master\"\n", false},
		{"legacy master", "allow_legacy_master = true\ntoken = \"synthetic-legacy-master\"\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.toml")
			if err := os.WriteFile(path, []byte(base+tc.extra), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadServer(path)
			if (err == nil) != tc.valid {
				t.Fatal("unexpected pool config admission", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "server.toml")
	if err := os.WriteFile(path, []byte("enrollment_login = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(path); err == nil {
		t.Fatal("login without explicit operator pool accepted")
	}
}
