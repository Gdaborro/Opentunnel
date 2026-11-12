package client

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/privatefile"
)

func TestReplacementReadinessCannotBeForgedByEmptyFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ready-fixture")
	_ = privatefile.WriteNew(file, []byte("wrong"))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := waitReplacementReady(ctx, file, strings.Repeat("a", 43), make(chan error)); err == nil {
		t.Fatal("wrong readiness token passed")
	}
}

func TestUpdateJournalRejectsEscapedRecoveryPaths(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "fixture.exe")
	journal := filepath.Join(dir, updateJournalName)
	base := updateTransaction{Version: 1, Executable: exe, Staged: exe + ".new-fixture.exe", Backup: exe + ".old-fixture", SHA256: strings.Repeat("a", 64), PreviousSHA256: strings.Repeat("b", 64), Parent: 1, Token: strings.Repeat("a", 43), ReadyFile: filepath.Join(dir, "ready-fixture"), StartedAt: time.Now().Unix()}
	write := func(tx updateTransaction) {
		t.Helper()
		data, err := json.Marshal(tx)
		if err != nil {
			t.Fatal(err)
		}
		if err := privatefile.Write(journal, data); err != nil {
			t.Fatal(err)
		}
	}
	write(base)
	if _, err := readUpdateTransaction(journal); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*updateTransaction){
		func(tx *updateTransaction) {
			tx.Backup = exe + ".old-dir" + string(filepath.Separator) + ".." + string(filepath.Separator) + "other-file"
		},
		func(tx *updateTransaction) { tx.Backup = filepath.Join(dir, "subdir", "fixture.exe.old-fixture") },
		func(tx *updateTransaction) { tx.Staged = filepath.Join(dir, "other.exe.new-fixture") },
		func(tx *updateTransaction) { tx.ReadyFile = journal },
		func(tx *updateTransaction) { tx.ReadyFile = filepath.Join(dir, "other-file") },
		func(tx *updateTransaction) { tx.Token = strings.Repeat("!", 43) },
	} {
		tx := base
		mutate(&tx)
		write(tx)
		if _, err := readUpdateTransaction(journal); err == nil {
			t.Fatal("invalid recovery path/token passed validation")
		}
	}
}

func TestUnconfirmedReplacementDeathCannotTriggerPathRollback(t *testing.T) {
	dir := t.TempDir()
	exe, staged, backup := filepath.Join(dir, "current"), filepath.Join(dir, "staged"), filepath.Join(dir, "backup")
	if err := os.WriteFile(exe, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := replaceExecutable(exe, staged, backup, func() error { return errReplacementStillRunning })
	if !errors.Is(err, errReplacementStillRunning) {
		t.Fatal("unconfirmed child death not reported")
	}
	if got, err := os.ReadFile(exe); err != nil || string(got) != "replacement" {
		t.Fatal("swapped path underneath the still-running replacement")
	}
	if got, err := os.ReadFile(backup); err != nil || string(got) != "previous" {
		t.Fatal("lost verified recovery backup")
	}
}

func TestBoundedUpdatePreflightOutput(t *testing.T) {
	var w boundedUpdateOutput
	p := []byte(strings.Repeat("x", 2048))
	if n, err := w.Write(p); err != nil || n != len(p) || len(w.data) != 1024 || !w.overflow {
		t.Fatal("preflight output not bounded")
	}
	if _, err := w.Write(p); err != nil || len(w.data) != 1024 {
		t.Fatal("repeated preflight output grew past the cap")
	}
}
func TestReplacementFailureDuringStabilityTriggersRollback(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ready-fixture")
	token := strings.Repeat("a", 43)
	_ = privatefile.WriteNew(file, []byte(token))
	exited := make(chan error, 1)
	go func() { time.Sleep(150 * time.Millisecond); exited <- errors.New("synthetic startup crash") }()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := waitReplacementReady(ctx, file, token, exited); err == nil {
		t.Fatal("crashed replacement was committed")
	}
}
func TestStagedUpdateTamperRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.exe")
	_ = os.WriteFile(path, []byte("verified fixture"), 0o600)
	digest, err := fileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	tx := updateTransaction{Staged: path, SHA256: digest}
	if err := verifyStagedUpdate(tx); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, []byte("changed after verification"), 0o600)
	if err := verifyStagedUpdate(tx); err == nil {
		t.Fatal("tampered staging file was executable")
	}
}
