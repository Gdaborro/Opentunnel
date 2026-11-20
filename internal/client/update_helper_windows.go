//go:build windows

package client

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func prepareUpdateHelper(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}

func updateProcessCreated(pid int) (uint64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

// Old journals did not record the replacement PID. Check exact executable
// paths as well as recorded owners before any recovery rename. Matching image
// names with unreadable process identity are not permission to risk a rollback.
func anotherUpdateImageAlive(images ...string) (bool, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID == uint32(os.Getpid()) {
			continue
		}
		candidate := false
		for _, image := range images {
			if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), filepath.Base(image)) {
				candidate = true
				break
			}
		}
		if !candidate {
			continue
		}
		alive, queryErr := updateProcessAlive(int(entry.ProcessID), images...)
		if queryErr != nil {
			// A process can disappear between snapshot and query. Retry once
			// without trusting PID reuse or an access-denied matching image.
			time.Sleep(time.Millisecond)
			alive, queryErr = updateProcessAlive(int(entry.ProcessID), images...)
		}
		if queryErr != nil {
			return false, queryErr
		}
		if alive {
			return true, nil
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return false, err
	}
	return false, nil
}

func moveUpdateNoReplace(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// Deliberately omit MOVEFILE_REPLACE_EXISTING, including dangling links.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
func validateActualUpdateParent(pid int, image string) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	actual := uint32(0)
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID == uint32(os.Getpid()) {
			actual = entry.ParentProcessID
			break
		}
	}
	if actual != uint32(pid) {
		return errors.New("update helper parent mismatch")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(windows.UTF16ToString(buf[:size])), filepath.Clean(image)) {
		return errors.New("update parent is not the expected executable")
	}
	return nil
}

func updateProcessAlive(pid int, images ...string) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
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
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return false, err
	}
	actual := windows.UTF16ToString(buf[:size])
	for _, image := range images {
		if sameExecutablePath(actual, image) {
			return true, nil
		}
	}
	return false, nil
}
