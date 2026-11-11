package client

import (
	"errors"
	"os"
	"strconv"
	"time"
)

// WaitForUpdateParent runs before the replacement performs single-instance
// detection. Without this handshake it could detect the still-running old
// client, exit, and leave no process after the updater exited successfully.
func WaitForUpdateParent(timeout time.Duration) error {
	raw := os.Getenv("OTU_UPDATE_PARENT_PID")
	_ = os.Unsetenv("OTU_UPDATE_PARENT_PID")
	var pid int
	if raw == "" {
		// Pre-handoff clients do not set the environment hint. Windows can
		// still identify an actual parent running this same executable (or
		// its renamed .old image), making the first upgrade safe too.
		pid = legacyUpdateParent()
		if pid == 0 {
			return nil
		}
	} else {
		var err error
		pid, err = strconv.Atoi(raw)
		if err != nil || pid <= 0 || pid == os.Getpid() {
			return errors.New("invalid updater parent PID")
		}
	}
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	return waitParentExit(pid, timeout)
}
