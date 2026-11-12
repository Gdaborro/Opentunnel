//go:build windows

package netenv

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// StartRecoveryWatcher starts this same executable in a minimal helper mode.
// It must confirm that it holds a handle to its real parent BEFORE settings
// change. The helper survives an ordinary forced parent termination and
// attempts journal recovery; next-start recovery remains the final backstop.
func StartRecoveryWatcher() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "-netenv-watch-parent", strconv.Itoa(os.Getpid()))
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer out.Close()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(out, 128)).ReadString('\n')
		if err == nil && strings.TrimSpace(line) != "ready" {
			err = errors.New("invalid recovery helper readiness")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err == nil {
			return nil
		}
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("recovery helper startup: %w", err)
	case err := <-done:
		return fmt.Errorf("recovery helper exited before readiness: %v", err)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return errors.New("recovery helper readiness timed out; settings unchanged")
	}
}

func runRecoveryWatcher(parent uint32) error {
	if parent == uint32(os.Getpid()) {
		return errors.New("recovery helper cannot watch itself")
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	actualParent := uint32(0)
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID == uint32(os.Getpid()) {
			actualParent = entry.ParentProcessID
			break
		}
	}
	if actualParent != parent {
		return errors.New("recovery helper parent mismatch")
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parent)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return err
	}
	image := windows.UTF16ToString(buf[:size])
	if !strings.EqualFold(filepath.Clean(image), filepath.Clean(exe)) && !strings.EqualFold(filepath.Clean(image), filepath.Clean(exe+".old")) {
		return errors.New("recovery helper was not launched by this client")
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		return err
	}
	result, err := windows.WaitForSingleObject(h, windows.INFINITE)
	if err != nil {
		return err
	}
	if result != windows.WAIT_OBJECT_0 {
		return errors.New("recovery parent wait failed")
	}
	mgr, err := NewManager()
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 5; attempt++ {
		err = mgr.Recover()
		if err == nil || errors.Is(err, ErrAlreadyRunning) {
			return nil
		}
		if attempt < 4 {
			time.Sleep(time.Second)
		}
	}
	return fmt.Errorf("recovery journal retained for manual retry: %w", err)
}
