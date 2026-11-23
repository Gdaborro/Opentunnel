package client

import (
	"os"
	"path/filepath"
	"testing"

	"opentunnel/internal/config"
)

func TestPlainBootstrapAllowedOnlyDuringFirstRun(t *testing.T) {
	store := &TokenStore{Dir: t.TempDir()}
	cfg := &config.ClientConf{AllowUntrustedBootstrap: true}
	device := &deviceFile{Created: true, Fingerprint: "synthetic-fingerprint"}
	if !plainBootstrapAllowed(cfg, device, store) {
		t.Fatal("new identity with explicit bootstrap consent was refused")
	}
	if err := store.MarkApproved(device.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if plainBootstrapAllowed(cfg, device, store) {
		t.Fatal("approved identity retained plain bootstrap")
	}
	device.Created = false
	if plainBootstrapAllowed(cfg, device, store) {
		t.Fatal("existing identity retained plain bootstrap")
	}
}

func TestApprovalReadFailureFailsClosed(t *testing.T) {
	store := &TokenStore{Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(store.Dir, "approved.flag"), []byte{0xff, 0x00, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}
	if !store.EverApproved("synthetic-fingerprint") {
		t.Fatal("corrupt approval state was treated as never approved")
	}
	cfg := &config.ClientConf{AllowUntrustedBootstrap: true}
	device := &deviceFile{Created: true, Fingerprint: "synthetic-fingerprint"}
	if plainBootstrapAllowed(cfg, device, store) {
		t.Fatal("corrupt approval state reopened plain bootstrap")
	}
}

func TestMarkApprovedReportsPersistenceFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &TokenStore{Dir: filepath.Join(blocker, "child")}
	if err := store.MarkApproved("synthetic-fingerprint"); err == nil {
		t.Fatal("approval persistence failure was discarded")
	}
}

func TestLoadOrCreateMarksOnlyMintedIdentityAsFirstRun(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.LoadOrCreate()
	if err != nil || !first.Created {
		t.Fatal("new identity was not marked as first run", err)
	}
	second, err := store.LoadOrCreate()
	if err != nil || second.Created {
		t.Fatal("existing identity was incorrectly marked as first run", err)
	}
}
