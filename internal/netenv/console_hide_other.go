//go:build !windows

package netenv

// HideConsole is a no-op outside Windows.
func HideConsole() {}
