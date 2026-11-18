// releasebundle generates/validates credential-free offline signing inputs.
// It never reads signing keys, signs a release, overwrites a file or publishes.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "release bundle:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	fs := flag.NewFlagSet("releasebundle", flag.ContinueOnError)
	dir := fs.String("directory", "", "exact release artifact directory")
	tag := fs.String("tag", "", "canonical release tag")
	channel := fs.String("channel", "candidate", "explicit signed channel: candidate/canary/stable")
	sequence := fs.Int64("sequence", 0, "monotonically increasing per-channel sequence")
	rollout := fs.Int("rollout", 0, "signed rollout percentage; defaults to no automatic installations")
	source := fs.String("source-commit", "", "exact clean source commit (40 lowercase hex)")
	toolchain := fs.String("toolchain", "", "exact Go toolchain, e.g. go1.27.4")
	minimum := fs.String("minimum-version", "", "reviewed minimum compatible update version")
	expires := fs.Duration("valid-for", 30*24*time.Hour, "signed freshness duration (maximum 90 days)")
	verify := fs.Bool("verify", false, "verify all local artifacts against an already signed bundle")
	rootChain := fs.String("root-chain", "", "bounded reviewed public root-rotation chain; never reads runtime trust state")
	sourceDirectory := fs.String("source-directory", ".", "clean frozen source checkout; HEAD must match source-commit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *dir == "" || *tag == "" {
		return errors.New("supply --directory and --tag; generation also needs sequence/source/toolchain/minimum")
	}
	root, err := reviewedRoot(*rootChain)
	if err != nil {
		return err
	}
	if *verify {
		return verifyDirectoryWithRoot(*dir, *tag, root)
	}
	entries, err := boundedInventory(*dir)
	if err != nil {
		return err
	}
	if *expires <= 0 || *expires > protocol.MaxReleaseValidity {
		return errors.New("valid-for must be between one second and 90 days")
	}
	now := time.Now().UTC()
	b := protocol.ReleaseBundle{Version: 1, Tag: *tag, Channel: *channel, Sequence: *sequence, RolloutPercent: *rollout, SourceCommit: *source, Toolchain: *toolchain, BuildRecipe: "otu-repro-v1", MinimumVersion: *minimum, RootVersion: root.Version, IssuedAt: now.Unix(), ExpiresAt: now.Add(*expires).Unix()}
	for _, entry := range entries {
		name := entry.Name()
		if _, allowed := protocol.ReleaseEnvelopePolicy(name); allowed {
			if name == protocol.ReleaseBundleName || name == protocol.ReleaseBundleSignature {
				return errors.New("existing bundle/signature must be preserved; use verify, never overwrite")
			}
			continue
		}
		platform, limit, allowed := protocol.ReleaseArtifactPolicy(name)
		if !allowed {
			return errors.New("unreviewed release artifact inventory member")
		}
		digest, size, err := artifactDigestBounded(filepath.Join(*dir, name), limit, -1)
		if err != nil {
			return err
		}
		b.Artifacts = append(b.Artifacts, protocol.ReleaseArtifact{Name: name, Platform: platform, SHA256: digest, Bytes: size})
	}
	sort.Slice(b.Artifacts, func(i, j int) bool { return b.Artifacts[i].Name < b.Artifacts[j].Name })
	if err := b.Validate(now); err != nil {
		return err
	}
	if err := protocol.ValidateCoordinatedReleaseInventory(b); err != nil {
		return err
	}
	if err := verifyFrozenSource(*sourceDirectory, b.SourceCommit, b.Toolchain); err != nil {
		return err
	}
	if err := verifyBuildConsistencyDocument(*dir, b); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := privatefile.WriteNew(filepath.Join(*dir, protocol.ReleaseBundleName), raw); err != nil {
		return err
	}
	fmt.Println("Created unsigned exact payload inventory and checked declared metadata against a clean source HEAD. This is not authenticated build provenance. Independent reproducibility, scoped signing and all release gates remain mandatory.")
	return nil
}

func artifactDigest(path string) (string, int64, error) {
	return artifactDigestBounded(path, 256<<20, -1)
}

func artifactDigestBounded(path string, maximum, declared int64) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum || (declared >= 0 && info.Size() != declared) {
		return "", 0, errors.New("linked/oversized release artifact")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", 0, errors.New("release artifact changed while opening")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maximum+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || n != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", 0, errors.New("artifact oversized or unreadable")
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}

func verifyDirectory(dir, tag string) error {
	root, err := reviewedRoot("")
	if err != nil {
		return err
	}
	return verifyDirectoryWithRoot(dir, tag, root)
}

func verifyDirectoryWithRoot(dir, tag string, root protocol.ReleaseRoot) error {
	raw, err := privatefile.ReadOnly(filepath.Join(dir, protocol.ReleaseBundleName), protocol.MaxBundleBytes)
	if err != nil {
		return err
	}
	sigRaw, err := privatefile.ReadOnly(filepath.Join(dir, protocol.ReleaseBundleSignature), 16<<10)
	if err != nil {
		return err
	}
	signatures, err := protocol.ParseBundleSignatures(sigRaw, root, true)
	if err != nil {
		return err
	}
	bundle, err := protocol.VerifyBundleWithRoot(raw, signatures, root, time.Now())
	if err != nil {
		return err
	}
	if bundle.Tag != tag {
		return errors.New("release bundle tag/root mismatch")
	}
	if err := protocol.ValidateCoordinatedReleaseInventory(bundle); err != nil {
		return err
	}
	entries, err := boundedInventory(dir)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, artifact := range bundle.Artifacts {
		seen[artifact.Name] = true
	}
	for _, entry := range entries {
		if seen[entry.Name()] {
			continue
		}
		limit, allowed := protocol.ReleaseEnvelopePolicy(entry.Name())
		if !allowed {
			return errors.New("unbound extra publication artifact")
		}
		if _, _, err := artifactDigestBounded(filepath.Join(dir, entry.Name()), limit, -1); err != nil {
			return err
		}
	}
	for _, artifact := range bundle.Artifacts {
		_, limit, _ := protocol.ReleaseArtifactPolicy(artifact.Name)
		digest, size, err := artifactDigestBounded(filepath.Join(dir, artifact.Name), limit, artifact.Bytes)
		if err != nil {
			return err
		}
		if digest != artifact.SHA256 || size != artifact.Bytes {
			return fmt.Errorf("artifact %s does not match signed payload inventory", artifact.Name)
		}
	}
	if err := verifyBuildConsistencyDocument(dir, bundle); err != nil {
		return err
	}
	fmt.Printf("Verified %s: exact %d-payload inventory and threshold signature, channel=%s, sequence=%d, rollout=%d%%, declared source=%s. Authenticated/reproducible-build provenance and release acceptance remain separate.\n", bundle.Tag, len(bundle.Artifacts), bundle.Channel, bundle.Sequence, bundle.RolloutPercent, bundle.SourceCommit)
	return nil
}

func boundedInventory(dir string) ([]os.DirEntry, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("release directory must be regular, not linked")
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(71)
	if (err != nil && err != io.EOF) || len(entries) > 70 {
		return nil, errors.New("release directory exceeds bounded inventory")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if entry.IsDir() || entry.Type() != 0 || seen[name] {
			return nil, errors.New("linked, duplicate or directory release inventory member")
		}
		seen[name] = true
	}
	return entries, nil
}

func reviewedRoot(chainPath string) (protocol.ReleaseRoot, error) {
	pub, err := base64.StdEncoding.DecodeString(client.ReleasePubKey)
	if err != nil || len(pub) != 32 {
		return protocol.ReleaseRoot{}, errors.New("invalid embedded release public root")
	}
	root := protocol.ReleaseRoot{Version: 1, Keys: []string{client.ReleasePubKey}, Threshold: 1, IssuedAt: 1767225600, ExpiresAt: 1893456000}
	if chainPath != "" {
		raw, err := privatefile.ReadOnly(chainPath, 256<<10)
		if err != nil {
			return root, err
		}
		var chain []protocol.RootRotation
		if serverpool.DecodeStrict(raw, &chain) != nil || len(chain) < 1 || len(chain) > 8 {
			return root, errors.New("reviewed public root chain invalid")
		}
		for _, rotation := range chain {
			entry, _ := json.Marshal(rotation)
			root, err = protocol.VerifyRootRotation(entry, root, time.Unix(rotation.Root.IssuedAt, 0))
			if err != nil {
				return root, err
			}
		}
	}
	return root, root.Validate(time.Now())
}

func verifyFrozenSource(dir, commit, toolchain string) error {
	if runtime.Version() != toolchain {
		return errors.New("builder toolchain differs from explicit source/build declaration")
	}
	head := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err := head.Output()
	if err != nil || strings.TrimSpace(string(out)) != commit {
		return errors.New("source HEAD does not match explicit frozen source commit")
	}
	status := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=normal")
	out, err = status.Output()
	if err != nil || len(bytes.TrimSpace(out)) != 0 {
		return errors.New("source checkout is not a frozen clean revision; provenance generation refused")
	}
	return nil
}

type buildConsistency struct {
	Version        int                        `json:"version"`
	Tag            string                     `json:"tag"`
	SourceCommit   string                     `json:"source_commit"`
	Toolchain      string                     `json:"toolchain"`
	BuildRecipe    string                     `json:"build_recipe"`
	MinimumVersion string                     `json:"minimum_version"`
	Artifacts      []protocol.ReleaseArtifact `json:"artifacts"`
}

func verifyBuildConsistencyDocument(dir string, bundle protocol.ReleaseBundle) error {
	raw, err := privatefile.ReadOnly(filepath.Join(dir, protocol.BuildProvenanceName), 256<<10)
	if err != nil {
		return errors.New("build consistency document unavailable")
	}
	var record buildConsistency
	if serverpool.DecodeStrict(raw, &record) != nil || protocol.RequireJSONFields(raw, "version", "tag", "source_commit", "toolchain", "build_recipe", "minimum_version", "artifacts") != nil || record.Version != 1 || record.Tag != bundle.Tag || record.SourceCommit != bundle.SourceCommit || record.Toolchain != bundle.Toolchain || record.BuildRecipe != bundle.BuildRecipe || record.MinimumVersion != bundle.MinimumVersion {
		return errors.New("build consistency document differs from bundle (not trusted provenance)")
	}
	expected := map[string]protocol.ReleaseArtifact{}
	for _, a := range bundle.Artifacts {
		if a.Name != protocol.BuildProvenanceName {
			expected[a.Name] = a
		}
	}
	if len(expected) != len(record.Artifacts) {
		return errors.New("build consistency document inventory incomplete")
	}
	for _, a := range record.Artifacts {
		if expected[a.Name] != a {
			return errors.New("build consistency artifact mismatch")
		}
		delete(expected, a.Name)
	}
	return nil
}
