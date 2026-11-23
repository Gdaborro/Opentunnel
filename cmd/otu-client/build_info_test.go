package main

import (
	"os"
	"path/filepath"
	"testing"

	"opentunnel/internal/version"
)

func TestBuildInfoPreflightCannotMintIdentityOrInvokeRecovery(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	if handled, err := handleBuildInfoCommand([]string{"--build-info"}); !handled || err != nil {
		t.Fatal(handled, err)
	}
	if handled, err := handleBuildInfoCommand([]string{"--print-default-config"}); !handled || err != nil {
		t.Fatal(handled, err)
	}
	if _, err := os.Lstat(filepath.Join(root, version.ProductName)); !os.IsNotExist(err) {
		t.Fatal("build query created runtime state", err)
	}
	if handled, err := handleBuildInfoCommand([]string{"--build-info", "--restore"}); !handled || err == nil {
		t.Fatal("read-only build query accepted networking flags")
	}
}
