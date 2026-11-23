package releasebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

const SBOMNamePrefix = "SBOM-otu-"

type BuildConsistency struct {
	Version        int                        `json:"version"`
	Tag            string                     `json:"tag"`
	SourceCommit   string                     `json:"source_commit"`
	Toolchain      string                     `json:"toolchain"`
	BuildRecipe    string                     `json:"build_recipe"`
	MinimumVersion string                     `json:"minimum_version"`
	Artifacts      []protocol.ReleaseArtifact `json:"artifacts"`
}

func VerifyBuildDocument(raw []byte, bundle protocol.ReleaseBundle) error {
	var record BuildConsistency
	if len(raw) > 256<<10 || serverpool.DecodeStrict(raw, &record) != nil || protocol.RequireJSONFields(raw, "version", "tag", "source_commit", "toolchain", "build_recipe", "minimum_version", "artifacts") != nil || record.Version != 1 || record.Tag != bundle.Tag || record.SourceCommit != bundle.SourceCommit || record.Toolchain != bundle.Toolchain || record.BuildRecipe != bundle.BuildRecipe || record.MinimumVersion != bundle.MinimumVersion {
		return errors.New("build consistency document differs from bundle; not trusted provenance")
	}
	expected := map[string]protocol.ReleaseArtifact{}
	for _, artifact := range bundle.Artifacts {
		if artifact.Name != protocol.BuildProvenanceName {
			expected[artifact.Name] = artifact
		}
	}
	if len(record.Artifacts) != len(expected) {
		return errors.New("build consistency document inventory incomplete")
	}
	var fields struct {
		Artifacts []json.RawMessage `json:"artifacts"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for i, artifact := range record.Artifacts {
		if err := protocol.RequireJSONFields(fields.Artifacts[i], "name", "platform", "sha256", "bytes"); err != nil {
			return err
		}
		if want, ok := expected[artifact.Name]; !ok || want != artifact {
			return errors.New("build consistency artifact digest/platform/size differs")
		}
		delete(expected, artifact.Name)
	}
	return nil
}

func validateReleaseText(raw []byte, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return errors.New("release text is empty, non-UTF8 or exceeds its bound")
	}
	for _, value := range raw {
		if value < 32 && value != '\n' && value != '\r' && value != '\t' {
			return errors.New("release text contains unsupported control bytes")
		}
	}
	return nil
}

// SBOMText is a deterministic Go module/settings inventory, not a full
// SPDX/CycloneDX analysis or authenticated build provenance. It is byte-bound to
// the chosen executable through its signed inventory and exact buildinfo.
func SBOMText(info *debug.BuildInfo) ([]byte, error) {
	if info == nil || len(info.Deps) > 1024 || len(info.Settings) > 64 {
		return nil, errors.New("SBOM build information unavailable or oversized")
	}
	raw := []byte(info.String())
	if err := validateReleaseText(raw, 2<<20); err != nil {
		return nil, err
	}
	return raw, nil
}

func verifyBinarySource(info *debug.BuildInfo, source SourceSnapshot, companion bool, toolchain string) error {
	dir := ""
	if companion {
		dir = "companions/xray/"
	}
	requirements, err := readModuleRequirements(source.Documents[dir+"go.mod"], source.Documents[dir+"go.sum"])
	if err != nil {
		return err
	}
	if requirements.Module != info.Main.Path || "go"+requirements.Go != toolchain {
		return errors.New("source module/Go requirement differs from executable buildinfo")
	}
	for _, dependency := range info.Deps {
		if requirements.Dependencies[dependency.Path] != dependency.Version || requirements.Sums[dependency.Path+" "+dependency.Version] != dependency.Sum {
			return errors.New("executable dependency version/checksum differs from source module inventory")
		}
	}
	return nil
}

// VerifyPayloads validates build/source/module/SBOM consistency from the exact
// bounded payload bytes. sourceDirectory optionally compares the source archive
// with a clean checkout's Git objects. It DOES NOT claim reproduction or signing
// authorization, even when all consistency checks pass.
func VerifyPayloads(ctx context.Context, dir string, bundle protocol.ReleaseBundle, sourceDirectory string) error {
	if err := bundle.Validate(time.Now()); err != nil {
		return err
	}
	if err := protocol.ValidateCoordinatedReleaseInventory(bundle); err != nil {
		return err
	}
	byName := map[string]protocol.ReleaseArtifact{}
	for _, artifact := range bundle.Artifacts {
		byName[artifact.Name] = artifact
	}
	sourceBytes, err := ReadArtifact(filepath.Join(dir, protocol.SourceArchiveName), byName[protocol.SourceArchiveName])
	if err != nil {
		return err
	}
	source, err := ReadSourceArchive(sourceBytes)
	if err != nil {
		return err
	}
	if sourceDirectory != "" {
		if err := VerifySourceCheckout(ctx, source, sourceDirectory, bundle.SourceCommit); err != nil {
			return err
		}
	}
	buildBytes, err := ReadArtifact(filepath.Join(dir, protocol.BuildProvenanceName), byName[protocol.BuildProvenanceName])
	if err != nil {
		return err
	}
	if err := VerifyBuildDocument(buildBytes, bundle); err != nil {
		return err
	}
	for _, artifact := range bundle.Artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if artifact.Name == protocol.SourceArchiveName || artifact.Name == protocol.BuildProvenanceName {
			continue
		}
		raw, err := ReadArtifact(filepath.Join(dir, artifact.Name), artifact)
		if err != nil {
			return err
		}
		if strings.Contains(artifact.Platform, "/") {
			info, err := ReadBinaryInfo(raw, artifact)
			if err != nil {
				return fmt.Errorf("%s: %w", artifact.Name, err)
			}
			if err := ValidateBinaryInfo(info, bundle, artifact); err != nil {
				return fmt.Errorf("%s: %w", artifact.Name, err)
			}
			_, _, _, companion, _ := executableRole(artifact)
			if err := verifyBinarySource(info, source, companion, bundle.Toolchain); err != nil {
				return err
			}
			if companion {
				noticeArtifact, ok := byName["SOURCE-AND-LICENSE-NOTICE-XRAY.md"]
				if !ok {
					return errors.New("companion source/license notice missing")
				}
				notice, err := ReadArtifact(filepath.Join(dir, noticeArtifact.Name), noticeArtifact)
				if err != nil || validateReleaseText(notice, 256<<10) != nil || !bytes.Equal(notice, source.Documents["companions/xray/README.md"]) {
					return errors.New("companion notice differs from exact archived source notice")
				}
			}
		} else if err := validateReleaseText(raw, 2<<20); err != nil {
			return err
		}
	}
	for _, product := range []string{"client", "server", "panel"} {
		name := "otu-" + product + "-linux-amd64"
		binaryBytes, err := ReadArtifact(filepath.Join(dir, name), byName[name])
		if err != nil {
			return err
		}
		info, err := ReadBinaryInfo(binaryBytes, byName[name])
		if err != nil {
			return err
		}
		want, err := SBOMText(info)
		if err != nil {
			return err
		}
		sbomName := SBOMNamePrefix + product + ".txt"
		observed, err := ReadArtifact(filepath.Join(dir, sbomName), byName[sbomName])
		if err != nil || !bytes.Equal(observed, want) {
			return errors.New("SBOM differs from exact selected executable module/settings inventory")
		}
	}
	return nil
}

func WriteBuildDocument(dir string, bundle protocol.ReleaseBundle) error {
	record := BuildConsistency{Version: 1, Tag: bundle.Tag, SourceCommit: bundle.SourceCommit, Toolchain: bundle.Toolchain, BuildRecipe: bundle.BuildRecipe, MinimumVersion: bundle.MinimumVersion, Artifacts: bundle.Artifacts}
	// JSON order is deterministic even if a caller assembled payloads from a
	// filesystem whose enumeration order differs on Windows and Linux.
	record.Artifacts = append([]protocol.ReleaseArtifact(nil), record.Artifacts...)
	sort.Slice(record.Artifacts, func(i, j int) bool { return record.Artifacts[i].Name < record.Artifacts[j].Name })
	for _, artifact := range bundle.Artifacts {
		if artifact.Name == protocol.BuildProvenanceName {
			return errors.New("build document cannot hash itself or overwrite existing evidence")
		}
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil || len(raw) > 256<<10 {
		return errors.New("build consistency document exceeds bound")
	}
	return privatefile.WriteNew(filepath.Join(dir, protocol.BuildProvenanceName), append(raw, '\n'))
}

func WriteSBOM(dir string, product string, info *debug.BuildInfo) error {
	if product != "client" && product != "server" && product != "panel" {
		return errors.New("SBOM product is not in the fixed release contract")
	}
	raw, err := SBOMText(info)
	if err != nil {
		return err
	}
	return privatefile.WriteNew(filepath.Join(dir, SBOMNamePrefix+product+".txt"), raw)
}

func regularArtifactFiles(dir string) ([]os.DirEntry, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("release directory is linked or not a directory")
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		return nil, errors.New("release directory changed while opening")
	}
	entries, err := f.ReadDir(65)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 64 {
		return nil, errors.New("release directory exceeds fixed inventory bound")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type() != 0 || seen[strings.ToLower(entry.Name())] {
			return nil, errors.New("release inventory has linked/directory/duplicate member")
		}
		seen[strings.ToLower(entry.Name())] = true
	}
	return entries, nil
}

func artifactRecord(dir, name string) (protocol.ReleaseArtifact, error) {
	platform, maximum, allowed := protocol.ReleaseArtifactPolicy(name)
	if !allowed {
		return protocol.ReleaseArtifact{}, errors.New("unreviewed artifact name in release directory")
	}
	raw, err := privatefile.ReadOnly(filepath.Join(dir, name), maximum)
	if err != nil || len(raw) == 0 {
		return protocol.ReleaseArtifact{}, errors.New("release artifact is unavailable, empty or oversized")
	}
	hash := sha256.Sum256(raw)
	return protocol.ReleaseArtifact{Name: name, Platform: platform, Bytes: int64(len(raw)), SHA256: hex.EncodeToString(hash[:])}, nil
}

// PrepareMetadata is a new-only offline build consistency producer. Existing
// binary artifacts are not overwritten or executed. Source/SBOM/provenance are
// generated only for a clean exact Git revision and a valid fixed build recipe.
// A failure may leave incomplete new metadata as review evidence; never erase it
// or label it authenticated/reproducible-build authorization.
func PrepareMetadata(ctx context.Context, dir, sourceDirectory string, bundle protocol.ReleaseBundle) error {
	policy := bundle
	policy.Artifacts = []protocol.ReleaseArtifact{{Name: "otu-client-windows-amd64.exe", Platform: "windows/amd64", Bytes: 1, SHA256: strings.Repeat("0", 64)}}
	if err := policy.Validate(time.Now()); err != nil {
		return err // malformed declarations must not create source/metadata evidence
	}
	if _, err := frozenGitFiles(ctx, sourceDirectory, bundle.SourceCommit); err != nil {
		return err
	}
	entries, err := regularArtifactFiles(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("metadata preparation requires a coordinated binary inventory")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		platform, _, allowed := protocol.ReleaseArtifactPolicy(name)
		if !allowed || !strings.Contains(platform, "/") {
			return errors.New("metadata preparation needs a binaries-only fresh inventory")
		}
		seen[name] = true
	}
	for _, name := range protocol.RequiredReleaseArtifacts() {
		platform, _, _ := protocol.ReleaseArtifactPolicy(name)
		if strings.Contains(platform, "/") && !seen[name] {
			return errors.New("metadata preparation is missing a required coordinated binary")
		}
	}
	for _, name := range append(protocol.RequiredReleaseArtifacts(), "SOURCE-AND-LICENSE-NOTICE-XRAY.md") {
		platform, _, _ := protocol.ReleaseArtifactPolicy(name)
		if strings.Contains(platform, "/") {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return errors.New("metadata output exists or is unavailable; preserve the previous build")
		}
	}
	if err := WriteSourceArchive(ctx, sourceDirectory, bundle.SourceCommit, filepath.Join(dir, protocol.SourceArchiveName)); err != nil {
		return err
	}
	sourceBytes, err := privatefile.ReadOnly(filepath.Join(dir, protocol.SourceArchiveName), 128<<20)
	if err != nil {
		return err
	}
	source, err := ReadSourceArchive(sourceBytes)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		artifact, err := artifactRecord(dir, entry.Name())
		if err != nil {
			return err
		}
		raw, err := ReadArtifact(filepath.Join(dir, artifact.Name), artifact)
		if err != nil {
			return err
		}
		info, err := ReadBinaryInfo(raw, artifact)
		if err != nil {
			return err
		}
		if err := ValidateBinaryInfo(info, bundle, artifact); err != nil {
			return fmt.Errorf("%s: %w", artifact.Name, err)
		}
		_, _, _, companion, _ := executableRole(artifact)
		if err := verifyBinarySource(info, source, companion, bundle.Toolchain); err != nil {
			return err
		}
		for _, product := range []string{"client", "server", "panel"} {
			if artifact.Name == "otu-"+product+"-linux-amd64" {
				if err := WriteSBOM(dir, product, info); err != nil {
					return err
				}
			}
		}
		if companion {
			notice := filepath.Join(dir, "SOURCE-AND-LICENSE-NOTICE-XRAY.md")
			if _, err := os.Lstat(notice); os.IsNotExist(err) {
				if err := privatefile.WriteNew(notice, source.Documents["companions/xray/README.md"]); err != nil {
					return err
				}
			}
		}
	}
	entries, err = regularArtifactFiles(dir)
	if err != nil {
		return err
	}
	bundle.Artifacts = nil
	for _, entry := range entries {
		artifact, err := artifactRecord(dir, entry.Name())
		if err != nil {
			return err
		}
		bundle.Artifacts = append(bundle.Artifacts, artifact)
	}
	sort.Slice(bundle.Artifacts, func(i, j int) bool { return bundle.Artifacts[i].Name < bundle.Artifacts[j].Name })
	if err := WriteBuildDocument(dir, bundle); err != nil {
		return err
	}
	artifact, err := artifactRecord(dir, protocol.BuildProvenanceName)
	if err != nil {
		return err
	}
	bundle.Artifacts = append(bundle.Artifacts, artifact)
	return VerifyPayloads(ctx, dir, bundle, sourceDirectory)
}
