//go:build !windows

package client

import (
	"errors"
	"os"
	"os/exec"
)

func prepareUpdateHelper(*exec.Cmd) {}
func validateActualUpdateParent(int, string) error {
	return errors.New("automatic replacement supervision is Windows-only")
}

func updateProcessCreated(int) (uint64, error) {
	return 0, errors.New("automatic replacement supervision is Windows-only")
}
func anotherUpdateImageAlive(...string) (bool, error) {
	return false, errors.New("pending automatic update recovery is Windows-only")
}
func moveUpdateNoReplace(source, destination string) error {
	if err := os.Link(source, destination); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		_ = os.Remove(destination) // only the new link this operation created
		return err
	}
	return nil
}
func updateProcessAlive(int, ...string) (bool, error) {
	return false, errors.New("pending automatic update recovery is Windows-only")
}
