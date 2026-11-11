//go:build !windows

package client

import (
	"errors"
	"syscall"
	"time"
)

func legacyUpdateParent() int { return 0 } // executable swaps are Windows-only

func waitParentExit(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("previous client did not exit within the update handoff budget")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
