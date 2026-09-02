//go:build windows

package netenv

import (
	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleWindow  = kernel32.NewProc("GetConsoleWindow")
	procShowWindow        = kernel32.NewProc("ShowWindow")
)

const swHide = 0

// HideConsole makes this process's console window invisible (the process
// keeps running). Used in double-click mode after the startup banner has
// been on screen long enough to read, so an accidental window close can no
// longer take the tunnel down. The stop path is the stop-otu.bat helper or
// Task Manager (settings still restore via the terminal-event handler when
// the process is killed).
func HideConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	_, _, _ = procShowWindow.Call(hwnd, swHide, 0)
}
