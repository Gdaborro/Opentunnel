package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedCompanionIdentity(t *testing.T) {
	if companionVersion != "opentunnel-xray 26.11.9-otu.1" {
		t.Fatal("reviewed companion version changed without profile migration")
	}
}
func TestCompanionCLIChild(t *testing.T) {
	if os.Getenv("OTU_XRAY_CLI_FIXTURE") != "1" {
		return
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("OTU_XRAY_CLI_ARGS")), &args) != nil {
		os.Exit(99)
	}
	os.Args = append([]string{os.Args[0]}, args...)
	main()
	os.Exit(0)
}

func TestCompanionCLIRejectsInvalidLocalConfigWithoutDumpingSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "malformed.json")
	const syntheticSecret = "synthetic-fixture-must-not-be-logged"
	if err := os.WriteFile(path, []byte(`{"privateKey":"`+syntheticSecret+`"`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"version"},
		{"run", "-test", "-c", path},
		{"run", "-test", "-c", filepath.Join(t.TempDir(), "missing")},
		{"run", "-test", "-c", "https://config.invalid/config.json"},
		{"run", "-unsupported"},
		{"unknown"},
	} {
		raw, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestCompanionCLIChild$")
		cmd.Env = append(os.Environ(), "OTU_XRAY_CLI_FIXTURE=1", "OTU_XRAY_CLI_ARGS="+string(raw))
		output, err := cmd.CombinedOutput()
		if args[0] == "version" {
			if err != nil || !strings.HasPrefix(string(output), companionVersion+" ") {
				t.Fatal("version CLI preflight failed")
			}
		} else if err == nil {
			t.Fatal("invalid companion arguments/config accepted")
		}
		if strings.Contains(string(output), syntheticSecret) || strings.Contains(string(output), path) {
			t.Fatal("companion emitted key-bearing config details or local paths")
		}
	}
}
