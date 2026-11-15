//go:build windows

package privatefile

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockFile(f *os.File) (func(), error) {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped) }, nil
}
