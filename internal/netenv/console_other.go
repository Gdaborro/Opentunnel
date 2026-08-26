//go:build !windows

package netenv

// InstallTerminalEventHandler is a no-op outside Windows; SIGINT/SIGTERM are
// handled by the caller via os/signal.
func InstallTerminalEventHandler(onTerminate func()) {}
