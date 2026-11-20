package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/releasebuild"
)

func TestRealRecipePayloadDirectoryMatchesSourceBuildAndSBOMContracts(t *testing.T) {
	dir := os.Getenv("OTU_RELEASEBUILD_RECIPE_DIR")
	source := os.Getenv("OTU_RELEASEBUILD_SOURCE_DIR")
	commit := os.Getenv("OTU_RELEASEBUILD_SOURCE_COMMIT")
	if dir == "" || source == "" || commit == "" {
		t.Skip("requires separately built exact-source recipe fixture inventory; never signs or executes artifacts")
	}
	entries, err := boundedInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	bundle := protocol.ReleaseBundle{Version: 1, Tag: "v1.1.99", Channel: "candidate", Sequence: 1, RolloutPercent: 0, SourceCommit: commit, Toolchain: "go1.27.4", BuildRecipe: releasebuild.Recipe, MinimumVersion: "v1.1.10", RootVersion: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	for _, entry := range entries {
		if _, envelope := protocol.ReleaseEnvelopePolicy(entry.Name()); envelope {
			continue
		}
		platform, limit, allowed := protocol.ReleaseArtifactPolicy(entry.Name())
		if !allowed {
			t.Fatal("unreviewed recipe file")
		}
		hash, size, err := artifactDigestBounded(filepath.Join(dir, entry.Name()), limit, -1)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Artifacts = append(bundle.Artifacts, protocol.ReleaseArtifact{Name: entry.Name(), Platform: platform, SHA256: hash, Bytes: size})
	}
	if err := releasebuild.VerifyPayloads(t.Context(), dir, bundle, source); err != nil {
		t.Fatal("real source/build recipe consistency rejected", err)
	}
}

func TestMetadataPreparationWithInvalidDeclarationCreatesNoEvidence(t *testing.T) {
	dir := t.TempDir()
	bundle := protocol.ReleaseBundle{Tag: "not-a-tag", SourceCommit: strings.Repeat("a", 40)}
	if err := releasebuild.PrepareMetadata(t.Context(), dir, t.TempDir(), bundle); err == nil {
		t.Fatal("invalid bundle policy accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid preparation produced source/metadata", err)
	}
}

func TestReadOnlyEnvelopeFilesCannotBeReplacedByDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := privatefile.EnsureDir(filepath.Join(dir, protocol.ReleaseBundleName)); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedInventory(dir); err == nil {
		t.Fatal("release metadata directory accepted as payload")
	}
}
