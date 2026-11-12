//go:build linux

package reality

import (
	"os"
	"os/exec"
	"syscall"
)

func prepareProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
}
func executableMode(path string) error         { return os.Chmod(path, 0o700) }
func containProcess(*exec.Cmd) (func(), error) { return func() {}, nil }
