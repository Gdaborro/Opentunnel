// releasebundle generates/validates credential-free offline signing inputs.
// It never reads signing keys, signs a release, overwrites a file or publishes.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/releasebuild"
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
	prepare := fs.Bool("prepare-metadata", false, "new-only exact Git source archive, executable module SBOMs and build consistency document; never signs")
	rootChain := fs.String("root-chain", "", "bounded reviewed public root-rotation chain; never reads runtime trust state")
	sourceDirectory := fs.String("source-directory", ".", "clean frozen source checkout; HEAD must match source-commit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *dir == "" || *tag == "" {
		return errors.New("supply --directory and --tag; generation also needs sequence/source/toolchain/minimum")
	}
	if *verify && *prepare {
		return errors.New("metadata preparation cannot be combined with signed verification")
	}
	root, err := reviewedRoot(*rootChain)
	if err != nil {
		return err
	}
	if *verify {
		return verifyDirectoryWithSource(*dir, *tag, root, *sourceDirectory)
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
	if *prepare {
		if err := verifyFrozenSource(*sourceDirectory, b.SourceCommit, b.Toolchain); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := releasebuild.PrepareMetadata(ctx, *dir, *sourceDirectory, b); err != nil {
			return err
		}
		fmt.Println("Prepared exact source/module/SBOM/build consistency payloads only. No signature, reproducible-build authorization, publication or readiness claim.")
		return nil
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := releasebuild.VerifyPayloads(ctx, *dir, b, *sourceDirectory); err != nil {
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
	return verifyDirectoryWithSource(dir, tag, root, "")
}

func verifyDirectoryWithSource(dir, tag string, root protocol.ReleaseRoot, sourceDirectory string) error {
	bundle, err := verifyInventoryWithRoot(dir, tag, root)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := releasebuild.VerifyPayloads(ctx, dir, bundle, sourceDirectory); err != nil {
		return err
	}
	fmt.Printf("Verified %s: exact %d-payload threshold-signed inventory and source/module/build-recipe/SBOM consistency; independent reproducibility and release acceptance are separate.\n", bundle.Tag, len(bundle.Artifacts))
	return nil
}

func verifyInventoryWithRoot(dir, tag string, root protocol.ReleaseRoot) (protocol.ReleaseBundle, error) {
	var empty protocol.ReleaseBundle
	raw, err := privatefile.ReadOnly(filepath.Join(dir, protocol.ReleaseBundleName), protocol.MaxBundleBytes)
	if err != nil {
		return empty, err
	}
	sigRaw, err := privatefile.ReadOnly(filepath.Join(dir, protocol.ReleaseBundleSignature), 16<<10)
	if err != nil {
		return empty, err
	}
	signatures, err := protocol.ParseBundleSignatures(sigRaw, root, true)
	if err != nil {
		return empty, err
	}
	bundle, err := protocol.VerifyBundleWithRoot(raw, signatures, root, time.Now())
	if err != nil {
		return empty, err
	}
	if bundle.Tag != tag {
		return empty, errors.New("release bundle tag/root mismatch")
	}
	if err := protocol.ValidateCoordinatedReleaseInventory(bundle); err != nil {
		return empty, err
	}
	entries, err := boundedInventory(dir)
	if err != nil {
		return empty, err
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
			return empty, errors.New("unbound extra publication artifact")
		}
		if _, _, err := artifactDigestBounded(filepath.Join(dir, entry.Name()), limit, -1); err != nil {
			return empty, err
		}
	}
	for _, artifact := range bundle.Artifacts {
		_, limit, _ := protocol.ReleaseArtifactPolicy(artifact.Name)
		digest, size, err := artifactDigestBounded(filepath.Join(dir, artifact.Name), limit, artifact.Bytes)
		if err != nil {
			return empty, err
		}
		if digest != artifact.SHA256 || size != artifact.Bytes {
			return empty, fmt.Errorf("artifact %s does not match signed payload inventory", artifact.Name)
		}
	}
	if err := verifyBuildConsistencyDocument(dir, bundle); err != nil {
		return empty, err
	}
	return bundle, nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return releasebuild.CheckFrozenSource(ctx, dir, commit)
}

type buildConsistency = releasebuild.BuildConsistency

func verifyBuildConsistencyDocument(dir string, bundle protocol.ReleaseBundle) error {
	raw, err := privatefile.ReadOnly(filepath.Join(dir, protocol.BuildProvenanceName), 256<<10)
	if err != nil {
		return errors.New("build consistency document unavailable")
	}
	return releasebuild.VerifyBuildDocument(raw, bundle)
}
