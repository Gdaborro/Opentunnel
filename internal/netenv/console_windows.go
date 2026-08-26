//go:build windows

package netenv

import (
	"golang.org/x/sys/windows"
)

const (
	ctrlCEvent        = 0
	ctrlBreakEvent    = 1
	ctrlCloseEvent    = 2
	ctrlLogoffEvent   = 5
	ctrlShutdownEvent = 6
)

var (
	procSetConsoleCtrlHandler = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
)

// InstallTerminalEventHandler registers a Windows control-console handler so
// that window-close, logoff, and shutdown still run the restore callback —
// events that Go's signal.Notify does not deliver.
//
// Ctrl+C / Ctrl+Break are intentionally NOT intercepted: they flow through
// os/signal as usual and the normal graceful path handles them.
func InstallTerminalEventHandler(onTerminate func()) {
	cb := windows.NewCallback(func(event uint32) uintptr {
		switch event {
		case ctrlCloseEvent, ctrlLogoffEvent, ctrlShutdownEvent:
			onTerminate()
			return 1 // handled
		}
		return 0 // pass through (Ctrl+C etc.)
	})
	_, _, _ = procSetConsoleCtrlHandler.Call(cb, 1)
}
