package client

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVersionParsingRejectsPrefixesSuffixesAndOverflow(t *testing.T) {
	for _, tag := range []string{"junk-v1.2.3", "v1.2.3-malicious", "v01.2.3", "v99999999999999999999999999.2.3", "v1.2.3\n"} {
		if _, _, _, ok := parseVersion(tag); ok {
			t.Errorf("invalid version accepted: %q", tag)
		}
	}
}

func TestUpdateDownloadURLsAreReleaseScoped(t *testing.T) {
	base := "https://github.com/" + updateRepo + "/releases/download/v1.1.5/manifest.sig"
	if !validReleaseAssetURL(base, "v1.1.5", "manifest.sig") {
		t.Fatal("valid asset URL rejected")
	}
	for _, url := range []string{
		"http://github.com/" + updateRepo + "/releases/download/v1.1.5/manifest.sig",
		"https://attacker.invalid/manifest.sig",
		base + "?token=unexpected", base + "#unexpected",
		"https://github.com/Other/Repo/releases/download/v1.1.5/manifest.sig",
	} {
		if validReleaseAssetURL(url, "v1.1.5", "manifest.sig") {
			t.Error("unscoped update URL accepted")
		}
	}
}

func TestUpdateParentHelper(t *testing.T) {
	if os.Getenv("OTU_UPDATE_TEST_HELPER") != "1" {
		return
	}
	time.Sleep(100 * time.Millisecond)
	os.Exit(0)
}

func TestLegacyParentProbeHelper(t *testing.T) {
	if os.Getenv("OTU_LEGACY_PARENT_TEST_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, legacyUpdateParent())
	os.Exit(0)
}

func TestLegacyUpdaterParentIsRecognizedOnFirstUpgrade(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows executable handoff")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestLegacyParentProbeHelper$")
	cmd.Env = append(os.Environ(), "OTU_LEGACY_PARENT_TEST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid != os.Getpid() {
		t.Fatal("legacy parent detection missed the actual same-image updater")
	}
}

func TestReplacementWaitsForPreviousProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestUpdateParentHelper$")
	cmd.Env = append(os.Environ(), "OTU_UPDATE_TEST_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Setenv("OTU_UPDATE_PARENT_PID", strconv.Itoa(cmd.Process.Pid))
	if err := WaitForUpdateParent(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement continued before old process exited")
	}
	if os.Getenv("OTU_UPDATE_PARENT_PID") != "" {
		t.Fatal("updater parent PID leaked to later subprocesses")
	}
}
