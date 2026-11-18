package main

import (
	"os"
	"path/filepath"
	"testing"

	"opentunnel/internal/version"
)

func TestStatusOnlyDoesNotMintIdentityOrRunRecovery(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	if handled, err := handleStatusCommand([]string{"--status"}); !handled || err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"device.json", "device_ssh", "snapshot.json", "crash.log"} {
		if _, err := os.Stat(filepath.Join(root, version.ProductName, name)); !os.IsNotExist(err) {
			t.Fatal("status opened runtime mutation path", name)
		}
	}
	if handled, err := handleStatusCommand([]string{"--status", "--auto-proxy"}); !handled || err == nil {
		t.Fatal("status accepted networking flag mixing")
	}
}
