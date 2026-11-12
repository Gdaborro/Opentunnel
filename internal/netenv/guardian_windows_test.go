//go:build windows

package netenv

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The helper's LOCALAPPDATA points to an empty test directory. No snapshot
// exists, so this process-lifecycle test does not read or modify HKCU.
func TestMain(m *testing.M) {
	if handled, err := RunRecoveryHelper(os.Args[1:]); handled {
		if err != nil {
			os.Exit(2)
		}
		if marker := os.Getenv("OTU_TEST_GUARDIAN_MARKER"); marker != "" {
			if err := os.WriteFile(marker, []byte("parent exit observed"), 0o600); err != nil {
				os.Exit(3)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func TestGuardianParentHelper(t *testing.T) {
	if os.Getenv("OTU_TEST_GUARDIAN_PARENT") != "1" {
		return
	}
	if err := StartRecoveryWatcher(); err != nil {
		t.Fatal(err)
	}
	fmt.Println("parent ready")
	time.Sleep(time.Minute)
}
func TestGuardianSurvivesForcedParentExit(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "guardian-observed-exit")
	cmd := exec.Command(os.Args[0], "-test.run=^TestGuardianParentHelper$")
	cmd.Env = append(os.Environ(), "LOCALAPPDATA="+dir, "OTU_TEST_GUARDIAN_PARENT=1", "OTU_TEST_GUARDIAN_MARKER="+marker)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(io.LimitReader(out, 128)).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "parent ready\n" {
			t.Fatalf("helper not ready: %q", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("guardian startup timeout")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("guardian did not survive parent termination")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
