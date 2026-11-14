//go:build !windows

package netenv

func retryableStateIO(error) bool { return false }
