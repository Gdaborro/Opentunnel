package netenv

import (
	"os"
	"time"

	"opentunnel/internal/privatefile"
)

// Windows antivirus/indexers can briefly hold a private file open while a
// flushed replacement is being installed. Retry only transient access/sharing
// failures for a short bounded interval; sustained ACL/disk failures still keep
// the old evidence and propagate. Every attempt remains an atomic private write.
func retryStateIO(operation func() error) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		err = operation()
		if err == nil || !retryableStateIO(err) {
			return err
		}
		if attempt < 4 {
			time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
		}
	}
	return err
}

func writeRecoveryState(path string, raw []byte) error {
	return retryStateIO(func() error { return privatefile.Write(path, raw) })
}

func newRecoveryState(path string, raw []byte) error {
	return retryStateIO(func() error { return privatefile.WriteNew(path, raw) })
}

func removeRecoveryState(path string) error {
	return retryStateIO(func() error { return os.Remove(path) })
}
