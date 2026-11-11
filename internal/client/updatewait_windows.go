//go:build windows

package client

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func legacyUpdateParent() int {
	exe, err := os.Executable()
	if err != nil {
		return 0
	}
	snapshot, err := syscall.CreateToolhelp32Snapshot(0x00000002, 0) // TH32CS_SNAPPROCESS
	if err != nil {
		return 0
	}
	defer syscall.CloseHandle(snapshot)
	entry := syscall.ProcessEntry32{Size: uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))}
	parent := uint32(0)
	for err = syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		if entry.ProcessID == uint32(os.Getpid()) {
			parent = entry.ParentProcessID
			break
		}
	}
	if parent == 0 || parent == uint32(os.Getpid()) {
		return 0
	}
	h, err := syscall.OpenProcess(0x1000, false, parent) // QUERY_LIMITED_INFORMATION
	if err != nil {
		return 0
	}
	defer syscall.CloseHandle(h)
	query := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	ok, _, _ := query.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		return 0
	}
	image := syscall.UTF16ToString(buf[:size])
	if strings.EqualFold(filepath.Clean(image), filepath.Clean(exe)) ||
		strings.EqualFold(filepath.Clean(image), filepath.Clean(exe+".old")) {
		return int(parent)
	}
	return 0
}

func waitParentExit(pid int, timeout time.Duration) error {
	h, err := syscall.OpenProcess(0x00100000, false, uint32(pid)) // SYNCHRONIZE only
	if err != nil {
		if errors.Is(err, syscall.Errno(87)) { // no such process
			return nil
		}
		return err
	}
	defer syscall.CloseHandle(h)
	result, err := syscall.WaitForSingleObject(h, uint32(timeout.Milliseconds()))
	if err != nil {
		return err
	}
	if result != syscall.WAIT_OBJECT_0 {
		return errors.New("previous client did not exit within the update handoff budget")
	}
	return nil
}
