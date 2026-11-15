package privatefile

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestExclusivePrivateLockIsReleasedAndKeepsStableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.lock")
	unlock, err := TryLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := TryLock(path); !errors.Is(err, ErrLocked) {
		if other != nil {
			other()
		}
		t.Fatal("competing lock accepted", err)
	}
	unlock()
	unlock()
	other, err := TryLock(path)
	if err != nil {
		t.Fatal("lock not released", err)
	}
	other()
}
