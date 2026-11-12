package netenv

import (
	"errors"
	"strconv"
)

// RunRecoveryHelper handles the private child mode before ordinary client
// startup. It cannot select arbitrary registry paths or a different identity.
func RunRecoveryHelper(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "-netenv-watch-parent" {
		return false, nil
	}
	if len(args) != 2 {
		return true, errors.New("invalid recovery helper arguments")
	}
	pid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || pid == 0 {
		return true, errors.New("invalid recovery parent")
	}
	return true, runRecoveryWatcher(uint32(pid))
}
