package privatefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadOnlyDoesNotRewriteProvisionedPermissionsAndBoundsInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provisioned")
	if err := os.WriteFile(path, []byte("synthetic operator input"), 0640); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0640); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := ReadOnly(path, 128); err != nil || string(data) != "synthetic operator input" {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatal("read-only operator input changed permissions")
	}
	if _, err := ReadOnly(path, 2); err == nil {
		t.Fatal("oversized credential accepted")
	}
	if _, err := ReadOnly(filepath.Dir(path), 128); err == nil {
		t.Fatal("nonregular input accepted")
	}
}
