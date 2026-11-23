package releasebuild

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"opentunnel/internal/protocol"
)

func syntheticPayloadInventory(t *testing.T) (string, protocol.ReleaseBundle) {
	t.Helper()
	dir := t.TempDir()
	bundle := fixtureBundle()
	appendArtifact := func(name string, raw []byte) {
		t.Helper()
		platform, _, allowed := protocol.ReleaseArtifactPolicy(name)
		if !allowed {
			t.Fatal("fixture role unsupported", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		bundle.Artifacts = append(bundle.Artifacts, protocol.ReleaseArtifact{Name: name, Platform: platform, Bytes: int64(len(raw)), SHA256: hex.EncodeToString(hash[:])})
	}
	for _, name := range protocol.RequiredReleaseArtifacts() {
		platform, _, _ := protocol.ReleaseArtifactPolicy(name)
		if !strings.Contains(platform, "/") {
			continue
		}
		artifact := protocol.ReleaseArtifact{Name: name, Platform: platform}
		appendArtifact(name, syntheticExecutable(fixtureBuildInfo(bundle, artifact), platform))
	}
	appendArtifact(protocol.SourceArchiveName, syntheticSource(t))
	for _, product := range []string{"client", "server", "panel"} {
		artifact := protocol.ReleaseArtifact{Name: "otu-" + product + "-linux-amd64", Platform: "linux/amd64"}
		raw, err := SBOMText(fixtureBuildInfo(bundle, artifact))
		if err != nil {
			t.Fatal(err)
		}
		appendArtifact(SBOMNamePrefix+product+".txt", raw)
	}
	if err := WriteBuildDocument(dir, bundle); err != nil {
		t.Fatal(err)
	}
	a, err := artifactRecord(dir, protocol.BuildProvenanceName)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Artifacts = append(bundle.Artifacts, a)
	return dir, bundle
}

func TestCompletePayloadConsistencyRequiresSourceModuleRecipeAndExactSBOM(t *testing.T) {
	dir, bundle := syntheticPayloadInventory(t)
	if err := VerifyPayloads(t.Context(), dir, bundle, ""); err != nil {
		t.Fatal("synthetic payload consistency fixture refused", err)
	}
	name := SBOMNamePrefix + "panel.txt"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("synthetic substituted SBOM"), 0600); err != nil {
		t.Fatal(err)
	}
	// Even an updated signed hash/build document cannot substitute a fake
	// module inventory for the exact selected executable's buildinfo.
	for i := range bundle.Artifacts {
		if bundle.Artifacts[i].Name == name {
			record, err := artifactRecord(dir, name)
			if err != nil {
				t.Fatal(err)
			}
			bundle.Artifacts[i] = record
		}
	}
	if err := os.Remove(filepath.Join(dir, protocol.BuildProvenanceName)); err != nil {
		t.Fatal(err)
	} // only this synthetic test's document
	without := bundle
	without.Artifacts = nil
	for _, a := range bundle.Artifacts {
		if a.Name != protocol.BuildProvenanceName {
			without.Artifacts = append(without.Artifacts, a)
		}
	}
	if err := WriteBuildDocument(dir, without); err != nil {
		t.Fatal(err)
	}
	for i := range bundle.Artifacts {
		if bundle.Artifacts[i].Name == protocol.BuildProvenanceName {
			record, err := artifactRecord(dir, protocol.BuildProvenanceName)
			if err != nil {
				t.Fatal(err)
			}
			bundle.Artifacts[i] = record
		}
	}
	if err := VerifyPayloads(t.Context(), dir, bundle, ""); err == nil {
		t.Fatal("fake SBOM passed consistent signature/hash declarations")
	}
}

func TestBuildDocumentNewOnlyAndMalformedSourceCannotBeAuthorizedByHash(t *testing.T) {
	dir, bundle := syntheticPayloadInventory(t)
	before, err := os.ReadFile(filepath.Join(dir, protocol.BuildProvenanceName))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteBuildDocument(dir, bundle); err == nil {
		t.Fatal("build metadata rewrote itself")
	}
	after, err := os.ReadFile(filepath.Join(dir, protocol.BuildProvenanceName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed publication modified old metadata", err)
	}
	if err := os.WriteFile(filepath.Join(dir, protocol.SourceArchiveName), []byte("not a source archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPayloads(t.Context(), dir, bundle, ""); err == nil {
		t.Fatal("malformed source archive passed")
	}
}
