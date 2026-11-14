//go:build windows

package netenv

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestTransientStateIOIsRetriedButSustainedDenialIsNotHidden(t *testing.T) {
	attempts := 0
	if err := retryStateIO(func() error {
		attempts++
		if attempts < 3 {
			return windows.ERROR_SHARING_VIOLATION
		}
		return nil
	}); err != nil || attempts != 3 {
		t.Fatal("transient private-state sharing failure not retried", err, attempts)
	}
	attempts = 0
	if err := retryStateIO(func() error {
		attempts++
		return windows.ERROR_ACCESS_DENIED
	}); !errors.Is(err, windows.ERROR_ACCESS_DENIED) || attempts != 5 {
		t.Fatal("sustained recovery-state denial was hidden or unbounded", err, attempts)
	}
}
