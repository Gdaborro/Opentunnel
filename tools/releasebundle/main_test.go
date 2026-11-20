package main

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

	"opentunnel/internal/protocol"
)

func syntheticInventory(t *testing.T) (string, protocol.ReleaseBundle, protocol.ReleaseRoot) {
	t.Helper()
	dir := t.TempDir()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := protocol.ReleaseRoot{Version: 2, Keys: []string{base64.StdEncoding.EncodeToString(pub)}, Threshold: 1, IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	bundle := protocol.ReleaseBundle{Version: 1, Tag: "v1.1.99", Channel: "candidate", Sequence: 5, RolloutPercent: 0, SourceCommit: strings.Repeat("a", 40), Toolchain: "go1.27.4", BuildRecipe: "otu-repro-v1", MinimumVersion: "v1.1.10", RootVersion: 2, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	// Pure signature/inventory fixture: these bytes are not executables, source
	// evidence, or trusted reproducible-build provenance. No artifact is run.
	for _, name := range protocol.RequiredReleaseArtifacts() {
		if name == protocol.BuildProvenanceName {
			continue
		}
		platform, limit, ok := protocol.ReleaseArtifactPolicy(name)
		if !ok {
			t.Fatal(name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("synthetic declared payload "+name), 0600); err != nil {
			t.Fatal(err)
		}
		hash, size, err := artifactDigestBounded(filepath.Join(dir, name), limit, -1)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Artifacts = append(bundle.Artifacts, protocol.ReleaseArtifact{Name: name, Platform: platform, SHA256: hash, Bytes: size})
	}
	record := buildConsistency{Version: 1, Tag: bundle.Tag, SourceCommit: bundle.SourceCommit, Toolchain: bundle.Toolchain, BuildRecipe: bundle.BuildRecipe, MinimumVersion: bundle.MinimumVersion, Artifacts: append([]protocol.ReleaseArtifact(nil), bundle.Artifacts...)}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, protocol.BuildProvenanceName), data, 0600); err != nil {
		t.Fatal(err)
	}
	hash, size, err := artifactDigestBounded(filepath.Join(dir, protocol.BuildProvenanceName), 256<<10, -1)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts = append(bundle.Artifacts, protocol.ReleaseArtifact{Name: protocol.BuildProvenanceName, Platform: "metadata", SHA256: hash, Bytes: size})
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, protocol.ReleaseBundleName), raw, 0600); err != nil {
		t.Fatal(err)
	}
	signature, err := json.Marshal([]protocol.RootSignature{{KeyID: protocol.ReleaseKeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.ReleaseBundleMessage(raw)))}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, protocol.ReleaseBundleSignature), signature, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, bundle, root
}

func TestVerifierUsesRotatedRootThresholdEnvelopeAndExactPayloadSet(t *testing.T) {
	dir, bundle, root := syntheticInventory(t)
	if _, err := verifyInventoryWithRoot(dir, bundle.Tag, root); err != nil {
		t.Fatal("synthetic threshold/inventory boundary rejected", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "otu-pool-linux-amd64"), []byte("unbound extra synthetic payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyInventoryWithRoot(dir, bundle.Tag, root); err == nil {
		t.Fatal("unbound allowlisted helper ignored")
	}
}

func TestFullVerifierRefusesSignatureOnlyPayloadDeclarations(t *testing.T) {
	dir, bundle, root := syntheticInventory(t)
	// A pure threshold/inventory fixture is not executable/source evidence.
	// The real CLI verifier cannot stop at its matching signature/hashes.
	if err := verifyDirectoryWithRoot(dir, bundle.Tag, root); err == nil {
		t.Fatal("correct synthetic signer/hash declarations authorized malformed binaries/source")
	}
}

func TestVerifierDoesNotTrustWrongKeyOrTruncatedInventory(t *testing.T) {
	dir, bundle, root := syntheticInventory(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := root
	wrong.Keys = []string{base64.StdEncoding.EncodeToString(pub)}
	if err := verifyDirectoryWithRoot(dir, bundle.Tag, wrong); err == nil {
		t.Fatal("another public root accepted")
	}
	if err := os.Remove(filepath.Join(dir, "otu-panel-linux-arm64")); err != nil {
		t.Fatal(err)
	}
	if err := verifyDirectoryWithRoot(dir, bundle.Tag, root); err == nil {
		t.Fatal("missing signed payload ignored")
	}
}

func TestDeclaredSizeAndDirectoryOverflowFailBeforeUnboundedRead(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "synthetic-oversized")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(8 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := artifactDigestBounded(file, 64<<20, 1); err == nil {
		t.Fatal("declared size mismatch accepted")
	}
	for i := 0; i < 71; i++ {
		name := strings.Repeat("x", i+1)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := boundedInventory(dir); err == nil {
		t.Fatal("directory overflow accepted")
	}
}

func TestBuilderRefusesGenericMetadataOnlyAndIncoherentFrozenDeclarations(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--directory", dir, "--tag", "v1.1.99", "--sequence", "1", "--source-commit", strings.Repeat("a", 40), "--toolchain", "go99.99.99", "--minimum-version", "v1.1.10"}); err == nil {
		t.Fatal("metadata-only fake build declaration accepted")
	}
	if _, err := os.Lstat(filepath.Join(dir, protocol.ReleaseBundleName)); !os.IsNotExist(err) {
		t.Fatal("failed builder wrote unsigned bundle", err)
	}
}
