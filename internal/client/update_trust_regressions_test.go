package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
)

func checkpointFixture(t *testing.T, rootVersion int64) (protocol.ReleaseBundle, protocol.ReleaseRoot) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := protocol.ReleaseRoot{Version: rootVersion, Keys: []string{base64.StdEncoding.EncodeToString(pub)}, Threshold: 1, IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	b := protocol.ReleaseBundle{Version: 1, Tag: "v1.1.99", Channel: "candidate", Sequence: 5, RolloutPercent: 10, SourceCommit: strings.Repeat("a", 40), Toolchain: "go1.27.4", BuildRecipe: "otu-repro-v1", MinimumVersion: "v1.1.10", RootVersion: rootVersion, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Artifacts: []protocol.ReleaseArtifact{{Name: updateAssetWin, Platform: "windows/amd64", SHA256: strings.Repeat("b", 64), Bytes: 4096}}}
	return b, root
}

func TestRootChainLossCannotReactivateEmbeddedTrust(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	b, root := checkpointFixture(t, 2)
	if err := saveBundleCheckpointWithRoot(b, root); err != nil {
		t.Fatal(err)
	}
	if _, err := activeReleaseRoot(); err == nil {
		t.Fatal("missing root chain selected embedded key despite root-2 bundle high-water")
	}
	store, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Dir, "release-bundle-checkpoint-candidate.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b.RootVersion = 1
	b.Sequence++
	oldRoot, err := embeddedReleaseRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveBundleCheckpointWithRoot(b, oldRoot); err == nil {
		t.Fatal("old signing root wrote a later sequence after partial restore")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("refused trust rollback overwrote checkpoint", err)
	}
}

func TestSameVersionRootConflictAndIncompleteCheckpointFailClosed(t *testing.T) {
	for _, member := range []string{"tag", "issued_at", "expires_at", "root_version", "root_digest", "sequence"} {
		t.Run(member, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", t.TempDir())
			b, root := checkpointFixture(t, 1)
			if err := saveBundleCheckpointWithRoot(b, root); err != nil {
				t.Fatal(err)
			}
			store, _ := NewTokenStore()
			path := filepath.Join(store.Dir, "release-bundle-checkpoint-candidate.json")
			raw, err := privatefile.Read(path, 4096)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, member)
			corrupt, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err := privatefile.Write(path, corrupt); err != nil {
				t.Fatal(err)
			}
			b.Sequence++
			if err := saveBundleCheckpointWithRoot(b, root); err == nil {
				t.Fatal("missing checkpoint field silently reset freshness", member)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(corrupt) {
				t.Fatal("corrupt checkpoint was discarded", err)
			}
		})
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	b, root := checkpointFixture(t, 1)
	if err := saveBundleCheckpointWithRoot(b, root); err != nil {
		t.Fatal(err)
	}
	_, conflict := checkpointFixture(t, 1)
	b.Sequence++
	if err := saveBundleCheckpointWithRoot(b, conflict); err == nil {
		t.Fatal("same-version root key equivocation accepted")
	}
}

func TestSignedCompatibilityMinimumEnforcedOnRunningClient(t *testing.T) {
	b, _ := checkpointFixture(t, 1)
	b.MinimumVersion = "v1.1.50"
	if err := checkBundleCompatibility(b, "1.1.10"); err == nil {
		t.Fatal("incompatible direct upgrade authorized")
	}
	if err := checkBundleCompatibility(b, "1.1.50"); err != nil {
		t.Fatal(err)
	}
	if err := checkBundleCompatibility(b, "not-a-version"); err == nil {
		t.Fatal("invalid running version disabled compatibility gate")
	}
}

func TestUpdateStatusExpiresWithoutAnotherSuccessfulNetworkCheck(t *testing.T) {
	before := CurrentUpdateStatus()
	t.Cleanup(func() { setUpdateStatus(before.State, before.Tag, before.ExpiresAt) })
	setUpdateStatus("signed channel metadata verified", "v1.1.99", time.Now().Add(-time.Second).Unix())
	if status := CurrentUpdateStatus(); !strings.Contains(status.State, "expired") {
		t.Fatal("expired metadata still displayed verified", status.State)
	}
}
