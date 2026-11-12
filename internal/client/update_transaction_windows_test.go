//go:build windows

package client

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/privatefile"
)

func TestInterruptedUpdateRecoveryChild(t *testing.T) {
	if os.Getenv("OTU_TEST_UPDATE_RECOVERY") != "1" {
		return
	}
	restarted, err := RecoverPendingUpdate()
	if err != nil {
		if os.Getenv("OTU_TEST_RECOVERY_EXPECT_ERROR") == "1" {
			os.Exit(0)
		}
		os.Exit(43)
	}
	if os.Getenv("OTU_TEST_RECOVERY_EXPECT_ERROR") == "1" {
		os.Exit(44)
	}
	if restarted {
		os.Exit(0)
	}
	if err := os.WriteFile(os.Getenv("OTU_TEST_RECOVERED"), []byte("verified previous executable started"), 0o600); err != nil {
		os.Exit(45)
	}
	os.Exit(0)
}

func TestReplacementTransactionChild(t *testing.T) {
	if os.Getenv("OTU_TEST_REPLACEMENT") != "1" {
		return
	}
	if os.Getenv("OTU_UPDATE_READY_TOKEN") == "" {
		_ = os.WriteFile(os.Getenv("OTU_TEST_RECOVERED"), []byte("original restarted"), 0o600)
		os.Exit(0)
	}
	if os.Getenv("OTU_TEST_FAIL_REPLACEMENT") == "1" {
		os.Exit(41)
	}
	if err := ReportUpdateReady(); err != nil {
		os.Exit(42)
	}
	time.Sleep(3 * time.Second)
	_ = os.WriteFile(os.Getenv("OTU_TEST_RECOVERED"), []byte("replacement stable"), 0o600)
	os.Exit(0)
}

func TestInterruptedExecutableTransactionRecoversNextStart(t *testing.T) {
	for _, mode := range []string{"stale swap", "not swapped", "wrong backup", "foreign install"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			appData := filepath.Join(dir, "appdata")
			t.Setenv("LOCALAPPDATA", appData)
			store, err := NewTokenStore()
			if err != nil {
				t.Fatal(err)
			}
			updates := filepath.Join(store.Dir, "updates")
			if err := privatefile.EnsureDir(updates); err != nil {
				t.Fatal(err)
			}
			source, err := os.ReadFile(os.Args[0])
			if err != nil {
				t.Fatal(err)
			}
			exe := filepath.Join(dir, "fixture.exe")
			backup := exe + ".old-fixture"
			staged := exe + ".new-fixture.exe"
			if err := os.WriteFile(backup, source, 0o700); err != nil {
				t.Fatal(err)
			}
			previous, err := fileDigest(backup)
			if err != nil {
				t.Fatal(err)
			}
			currentBytes := append(bytes.Clone(source), []byte("synthetic interrupted-update marker")...)
			if mode == "not swapped" {
				currentBytes = source
			}
			if err := os.WriteFile(exe, currentBytes, 0o700); err != nil {
				t.Fatal(err)
			}
			current, err := fileDigest(exe)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(staged, []byte("preserve staged evidence"), 0o600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "child-result")
			tx := updateTransaction{Version: 1, Executable: exe, Staged: staged, Backup: backup, SHA256: current, PreviousSHA256: previous, Parent: 2147483646, Helper: 2147483645, Token: strings.Repeat("a", 43), Args: []string{"-test.run=^TestInterruptedUpdateRecoveryChild$"}, ReadyFile: filepath.Join(updates, "ready-fixture"), StartedAt: time.Now().Add(-48 * time.Hour).Unix()}
			if mode == "wrong backup" {
				if err := os.WriteFile(backup, []byte("tampered rollback"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign install" {
				tx.Executable = filepath.Join(dir, "other-install.exe")
				tx.Staged = tx.Executable + ".new-fixture.exe"
				tx.Backup = tx.Executable + ".old-fixture"
			}
			journal := filepath.Join(updates, updateJournalName)
			raw, err := json.Marshal(tx)
			if err != nil {
				t.Fatal(err)
			}
			if err := privatefile.WriteNew(journal, raw); err != nil {
				t.Fatal(err)
			}
			expectError := mode == "wrong backup" || mode == "foreign install"
			cmd := exec.Command(exe, "-test.run=^TestInterruptedUpdateRecoveryChild$")
			cmd.Env = append(withoutUpdateEnvironment(os.Environ()), "OTU_TEST_UPDATE_RECOVERY=1", "OTU_TEST_RECOVERED="+marker)
			if expectError {
				cmd.Env = append(cmd.Env, "OTU_TEST_RECOVERY_EXPECT_ERROR=1")
			}
			if err := cmd.Run(); err != nil {
				t.Fatal("copied recovery executable failed", err)
			}
			if expectError {
				if got, err := fileDigest(exe); err != nil || got != current {
					t.Fatal("refused recovery changed the current executable")
				}
				if _, err := os.Stat(journal); err != nil {
					t.Fatal("refused recovery discarded its journal")
				}
				return
			}
			deadline := time.Now().Add(8 * time.Second)
			for {
				if data, err := os.ReadFile(marker); err == nil && string(data) == "verified previous executable started" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("next-start recovery did not start the verified previous executable")
				}
				time.Sleep(50 * time.Millisecond)
			}
			if got, err := fileDigest(exe); err != nil || got != previous {
				t.Fatal("next-start recovery did not restore the original digest")
			}
			if _, err := os.Stat(journal); !os.IsNotExist(err) {
				t.Fatal("completed recovery left a transaction journal")
			}
			if _, err := os.Stat(staged); err != nil {
				t.Fatal("recovery discarded staged evidence")
			}
			if mode == "stale swap" {
				files, err := filepath.Glob(exe + ".failed-*")
				if err != nil || len(files) != 1 {
					t.Fatal("interrupted replacement evidence was not retained")
				}
			}
		})
	}
}

// Real Windows executable rename/readiness/rollback, copied TEST executables
// and private temp state only. No installed-client or proxy/registry changes.
func TestExecutableTransactionCommitsOrRollsBack(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "startup failure"}[fail], func(t *testing.T) {
			dir := t.TempDir()
			exe := filepath.Join(dir, "fixture.exe")
			staged := exe + ".new-fixture.exe"
			source, err := os.ReadFile(os.Args[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(exe, source, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(staged, source, 0o700); err != nil {
				t.Fatal(err)
			}
			digest, err := fileDigest(exe)
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "child-result")
			t.Setenv("OTU_TEST_REPLACEMENT", "1")
			t.Setenv("OTU_TEST_RECOVERED", marker)
			if fail {
				t.Setenv("OTU_TEST_FAIL_REPLACEMENT", "1")
			} else {
				t.Setenv("OTU_TEST_FAIL_REPLACEMENT", "0")
			}
			tx := updateTransaction{Version: 1, Executable: exe, Staged: staged, Backup: exe + ".old-fixture", SHA256: digest, PreviousSHA256: digest, Parent: 1, Token: strings.Repeat("a", 43), Args: []string{"-test.run=^TestReplacementTransactionChild$"}, ReadyFile: filepath.Join(dir, "ready-fixture"), StartedAt: time.Now().Unix()}
			journal := filepath.Join(dir, updateJournalName)
			data, _ := json.Marshal(tx)
			if err := privatefile.WriteNew(journal, data); err != nil {
				t.Fatal(err)
			}
			err = executeUpdateTransaction(journal, tx)
			if fail && err == nil {
				t.Fatal("startup failure was committed")
			}
			if !fail && err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(8 * time.Second)
			for {
				if data, err := os.ReadFile(marker); err == nil {
					want := "replacement stable"
					if fail {
						want = "original restarted"
					}
					if string(data) != want {
						t.Fatal("incorrect recovery outcome")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child lifecycle outcome missing")
				}
				time.Sleep(50 * time.Millisecond)
			}
			if _, err := os.Stat(journal); !os.IsNotExist(err) {
				t.Fatal("completed update left its journal")
			}
			if fail {
				if _, err := os.Stat(tx.Backup); !os.IsNotExist(err) {
					t.Fatal("rollback did not restore original path")
				}
			} else {
				if _, err := os.Stat(tx.Backup); err != nil {
					t.Fatal("successful update discarded previous executable")
				}
			}
		})
	}
}
