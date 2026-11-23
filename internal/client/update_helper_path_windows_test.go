//go:build windows

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestUpdateHelperRejectsForeignJournalBeforeLockOrACLChange(t *testing.T) {
	t.Setenv("LOCALAPPDATA", filepath.Join(t.TempDir(), "appdata"))
	dir := t.TempDir()
	icacls := func() string {
		t.Helper()
		out, err := exec.Command("icacls.exe", dir).CombinedOutput()
		if err != nil {
			t.Fatal("read directory ACL", err, string(out))
		}
		return string(out)
	}
	before := icacls()
	for _, path := range []string{dir, filepath.Join(dir, "update-transaction.json")} {
		handled, err := RunUpdateHelper([]string{"-update-supervise", path})
		if !handled || err == nil {
			t.Fatalf("foreign helper path accepted: %q, %v", path, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "update-supervision.lock")); !os.IsNotExist(err) {
			t.Fatal("foreign helper path created a lock")
		}
	}
	if after := icacls(); after != before {
		t.Fatalf("foreign helper path changed directory ACL\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
