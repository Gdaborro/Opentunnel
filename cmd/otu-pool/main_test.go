package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/serverpool"
)

// Run the actual command entry point in an isolated test subprocess. Only
// synthetic, newly generated operator keys are used; none are printed/read
// into test output, and no listener, deploy command or release signer runs.
func TestPoolCommandHelper(t *testing.T) {
	if os.Getenv("OTU_SYNTHETIC_POOL_COMMAND") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			flag.CommandLine = flag.NewFlagSet("synthetic pool command", flag.ExitOnError)
			main()
			return
		}
	}
	t.Fatal("synthetic command arguments missing")
}

func TestPoolProvisioningCommandCreatesAndExportsWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "synthetic-profile-key.pem")
	run := func(wantOK bool, args ...string) string {
		t.Helper()
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestPoolCommandHelper$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "OTU_SYNTHETIC_POOL_COMMAND=1", "TMPDIR="+dir)
		cmd.Dir = dir
		raw, err := cmd.CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("synthetic pool command result: %v (%s)", err, raw)
		}
		return strings.TrimSpace(strings.TrimSuffix(string(raw), "PASS\n"))
	}
	run(true, "--gen-key", "--key", keyPath)
	id := run(true, "--print-id", "--key", keyPath)
	if !serverpool.ValidID(id) {
		t.Fatal("public operator fingerprint invalid")
	}
	run(false, "--gen-key", "--key", keyPath)
	cfgPath := filepath.Join(dir, "server.toml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("pool_id = %q\nenrollment_login = true\n", id)), 0600); err != nil {
		t.Fatal(err)
	}
	nodesPath := filepath.Join(dir, "nodes.json")
	nodes := []serverpool.Node{{ID: "entry", Name: "Synthetic entry", Address: "entry.example:443", Pins: []string{strings.Repeat("a", 64)}, WSPath: "/stream"}}
	raw, _ := json.Marshal(nodes)
	if err := os.WriteFile(nodesPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "pool.json")
	run(true, "--export", output, "--key", keyPath, "--c", cfgPath, "--nodes", nodesPath, "--name", "Synthetic command pool", "--valid-for", "1h")
	p, err := serverpool.Load(output, time.Now())
	if err != nil || p.ID != id || !p.LoginRequired || !p.ApprovalRequired || !serverpool.ValidID(p.AuthorityID) {
		t.Fatal("export did not bind signed authority", err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	run(false, "--export", output, "--key", keyPath, "--c", cfgPath, "--nodes", nodesPath, "--name", "Synthetic replacement name")
	after, err := os.ReadFile(output)
	if err != nil || string(before) != string(after) {
		t.Fatal("command overwrote existing profile")
	}
}
