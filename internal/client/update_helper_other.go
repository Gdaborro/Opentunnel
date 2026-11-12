//go:build !windows

package client

import (
	"errors"
	"os/exec"
)

func prepareUpdateHelper(*exec.Cmd) {}
func validateActualUpdateParent(int, string) error {
	return errors.New("automatic replacement supervision is Windows-only")
}
func updateProcessAlive(int, ...string) (bool, error) {
	return false, errors.New("pending automatic update recovery is Windows-only")
}
