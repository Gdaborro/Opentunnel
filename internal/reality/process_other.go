//go:build !windows && !linux

package reality

import (
	"errors"
	"os"
	"os/exec"
)

func prepareProcess(*exec.Cmd)         {}
func executableMode(path string) error { return os.Chmod(path, 0o700) }
func containProcess(*exec.Cmd) (func(), error) {
	return nil, errors.New("managed companion process containment is unavailable on this OS")
}
