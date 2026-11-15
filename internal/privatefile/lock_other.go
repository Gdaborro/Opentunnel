//go:build !windows

package privatefile

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(f *os.File) (func(), error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }, nil
}
