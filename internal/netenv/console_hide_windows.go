//go:build windows

package netenv

import (
	"golang.org/x/sys/windows"
)

var (
	user32dll          = windows.NewLazySystemDLL("user32.dll")
	procGetConsoleWindow = user32dll.NewProc("GetConsoleWindow")
	procShowWindow       = user32dll.NewProc("ShowWindow")
)

const swHide = 0

// HideConsole makes this process's console window invisible (the process
// keeps running). Used in double-click mode after the startup banner has
// been on screen long enough to read, so an accidental window close can no
// longer take the tunnel down. Never panics: on any failure it simply
// leaves the console visible (a cosmetic issue, not a crash).
func HideConsole() {
	defer func() {
		_ = recover() // missing proc / no console — leave the window alone
	}()
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	_, _, _ = procShowWindow.Call(hwnd, swHide, 0)
}
