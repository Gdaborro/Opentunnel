//go:build windows

package netenv

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"opentunnel/internal/privatefile"
)

const processOwnerName = "client-owner.json"

// RecordProcessOwner publishes this instance's identity for the checked --stop
// operation. It contains no credentials or network settings.
func RecordProcessOwner() error {
	mgr, err := NewManager()
	if err != nil {
		return err
	}
	owner, err := currentWindowsOwner()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(owner)
	if err != nil {
		return err
	}
	return privatefile.Write(filepath.Join(mgr.Dir, processOwnerName), raw)
}

func readProcessOwner(dir string) (journalOwner, error) {
	var owner journalOwner
	raw, err := privatefile.Read(filepath.Join(dir, processOwnerName), 4096)
	if err != nil {
		return owner, err
	}
	if err := json.Unmarshal(raw, &owner); err != nil {
		return owner, errors.New("client owner record is invalid")
	}
	if owner.PID <= 0 || owner.PID == os.Getpid() || owner.Created == 0 || strings.TrimSpace(owner.Image) == "" {
		return owner, errors.New("client owner record is incomplete or targets this process")
	}
	return owner, nil
}

// StopClient terminates only the recorded, still-identical client process.
// It does not restore settings itself: the caller performs bounded journal
// recovery after this process has exited, avoiding any self-restore race.
func StopClient() error {
	mgr, err := NewManager()
	if err != nil {
		return err
	}
	owner, err := readProcessOwner(mgr.Dir)
	if err != nil {
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(owner.PID))
	if err != nil {
		return fmt.Errorf("recorded client is not running or is not accessible: %w", err)
	}
	defer windows.CloseHandle(h)
	alive, err := windowsOwnerAlive(owner)
	if err != nil || !alive {
		return errors.New("recorded client PID was reused or its creation time changed; refusing termination")
	}
	image, err := processImage(h)
	if err != nil || !strings.EqualFold(filepath.Clean(image), filepath.Clean(owner.Image)) {
		return errors.New("recorded client executable path changed; refusing termination")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil || code != 259 {
		return errors.New("recorded client already exited")
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		result, err := windows.WaitForSingleObject(h, 100)
		if err != nil {
			return err
		}
		if result == windows.WAIT_OBJECT_0 {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("recorded client did not exit after verified termination")
		}
	}
}

func processImage(h windows.Handle) (string, error) {
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}
