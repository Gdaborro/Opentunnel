//go:build windows

package netenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"opentunnel/internal/version"
)

// Production and fixture builds use the same process identities and exclusive
// OS lease. This file performs no registry reads, writes or notifications.
func acquireWindowsLease(dir string) (func(), error) {
	path, err := windows.UTF16PtrFromString(filepath.Join(dir, "network-settings.lease"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return nil, ErrAlreadyRunning
	}
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}

func currentWindowsOwner() (journalOwner, error) {
	exe, err := os.Executable()
	if err != nil {
		return journalOwner{}, err
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		return journalOwner{}, err
	}
	return journalOwner{PID: os.Getpid(), Image: exe, Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}, nil
}

func windowsOwnerAlive(o journalOwner) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(o.PID))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false, err
	}
	if code != 259 {
		return false, nil
	} // STILL_ACTIVE
	if o.Created == 0 {
		return isOtuProcess(uint32(o.PID)), nil
	} // legacy journal
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return false, err
	}
	return o.Created == uint64(created.HighDateTime)<<32|uint64(created.LowDateTime), nil
}

func processAlive(pid uint32) bool {
	alive, err := windowsOwnerAlive(journalOwner{PID: int(pid)})
	return err == nil && alive
}

func isOtuProcess(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return false
	}
	name := strings.ToLower(filepath.Base(windows.UTF16ToString(buf[:size])))
	name = strings.TrimSuffix(name, ".old")
	return name == strings.ToLower(version.ProcessID)+".exe" || name == strings.ToLower(version.ProcessID)+"-windows-amd64.exe"
}
