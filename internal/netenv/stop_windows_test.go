//go:build windows

package netenv

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"opentunnel/internal/privatefile"
)

func processHandleForTest(pid int) (windows.Handle, error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}

func processCreatedForTest(h windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

func updateProcessAliveForTest(pid int) (bool, error) {
	h, err := processHandleForTest(pid)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false, err
	}
	return code == 259, nil
}

func TestStopClientTerminatesOnlyRecordedProcess(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	fixturePath := filepath.Join(t.TempDir(), "synthetic-settings.json")
	if err := os.WriteFile(fixturePath, []byte(`{"keys":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTU_NETENV_FIXTURE", fixturePath)
	first := exec.Command("cmd.exe", "/c", "timeout", "/t", "60")
	second := exec.Command("cmd.exe", "/c", "timeout", "/t", "60")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(); err != nil {
		_ = first.Process.Kill()
		t.Fatal(err)
	}
	defer func() {
		_ = first.Process.Kill()
		_ = second.Process.Kill()
		_, _ = first.Process.Wait()
		_, _ = second.Process.Wait()
	}()
	h, err := processHandleForTest(first.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	created, err := processCreatedForTest(h)
	_ = windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	owner := journalOwner{PID: first.Process.Pid, Image: os.Args[0], Created: created}
	// Use the actual child image rather than the test executable.
	h, err = processHandleForTest(first.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	owner.Image, err = processImage(h)
	_ = windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(owner)
	mgr, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefile.Write(filepath.Join(mgr.Dir, processOwnerName), raw); err != nil {
		t.Fatal(err)
	}
	if err := StopClient(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- first.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("recorded child was not terminated")
	}
	alive, err := updateProcessAliveForTest(second.Process.Pid)
	if err != nil || !alive {
		t.Fatal("unrecorded same-name child was terminated", err)
	}
}
