package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

// No unfinished hardening tag/floor is chosen by this implementation.
// Release stamping must set this to the reviewed milestone's version before
// promotion; once configured, newer releases cannot strip bundle verification.
var ReleaseBundleFloor string

const legacySingleArtifactCeiling = "v1.1.10"

func requiresReleaseBundle(tag string) bool {
	return isNewer(legacySingleArtifactCeiling, tag) || (ReleaseBundleFloor != "" && (tag == ReleaseBundleFloor || isNewer(ReleaseBundleFloor, tag)))
}

type bundleCheckpoint struct {
	Channel     string `json:"channel"`
	Sequence    int64  `json:"sequence"`
	Tag         string `json:"tag"`
	Digest      string `json:"digest"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	RootVersion int64  `json:"root_version"`
	RootDigest  string `json:"root_digest"`
}

type releaseRootCheckpoint struct {
	Version  int64  `json:"version"`
	Digest   string `json:"digest"`
	IssuedAt int64  `json:"issued_at"`
}
type signedBundle struct {
	Bundle protocol.ReleaseBundle
	Raw    []byte
}

func embeddedReleaseRoot() (protocol.ReleaseRoot, error) {
	pub, err := base64.StdEncoding.DecodeString(ReleasePubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return protocol.ReleaseRoot{}, errors.New("invalid embedded release trust root")
	}
	return protocol.ReleaseRoot{Version: 1, Keys: []string{ReleasePubKey}, Threshold: 1, IssuedAt: 1767225600, ExpiresAt: 1893456000}, nil
}

func activeReleaseRoot() (protocol.ReleaseRoot, error) {
	root, err := embeddedReleaseRoot()
	if err != nil {
		return root, err
	}
	store, err := NewTokenStore()
	if err != nil {
		return root, err
	}
	raw, err := privatefile.Read(filepath.Join(store.Dir, "release-root-chain.json"), 256<<10)
	if errors.Is(err, os.ErrNotExist) {
		if err := checkRootHighWater(store.Dir, root); err != nil {
			return root, err
		}
		return root, root.Validate(time.Now())
	}
	if err != nil {
		return root, err
	}
	var chain []protocol.RootRotation
	if serverpool.DecodeStrict(raw, &chain) != nil || len(chain) == 0 || len(chain) > 8 {
		return root, errors.New("stored release-root chain is corrupt; refusing embedded-root fallback")
	}
	for _, rotation := range chain {
		entry, _ := json.Marshal(rotation)
		// Expired historical roots are verified at their signed issuance time;
		// only the currently active root is required to be fresh now.
		root, err = protocol.VerifyRootRotation(entry, root, time.Unix(rotation.Root.IssuedAt, 0))
		if err != nil {
			return root, err
		}
	}
	if err := checkRootHighWater(store.Dir, root); err != nil {
		return root, err
	}
	return root, root.Validate(time.Now())
}

func readBundleCheckpoint(path, channel string) (bundleCheckpoint, error) {
	var previous bundleCheckpoint
	raw, err := privatefile.Read(path, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return previous, nil
	}
	if err != nil {
		return previous, err
	}
	if serverpool.DecodeStrict(raw, &previous) != nil || protocol.RequireJSONFields(raw, "channel", "sequence", "tag", "digest", "issued_at", "expires_at", "root_version", "root_digest") != nil || previous.Channel != channel || previous.Sequence < 1 || !protocol.ValidReleaseTag(previous.Tag) || !serverpool.ValidID(previous.Digest) || previous.IssuedAt < 1 || previous.IssuedAt > time.Now().Unix()+300 || previous.ExpiresAt <= previous.IssuedAt || previous.ExpiresAt-previous.IssuedAt > int64(protocol.MaxReleaseValidity/time.Second) || previous.RootVersion < 1 || !serverpool.ValidID(previous.RootDigest) {
		return previous, errors.New("bundle checkpoint corrupt; refusing freshness or root reset")
	}
	return previous, nil // expiry is retained, not an excuse to erase high-water state
}

func checkRootHighWater(dir string, root protocol.ReleaseRoot) error {
	digest, err := root.Digest()
	if err != nil {
		return err
	}
	check := func(version int64, expected string) error {
		if root.Version < version || (root.Version == version && digest != expected) {
			return errors.New("release root is below or conflicts with observed trust; restore the reviewed complete chain, no embedded fallback")
		}
		return nil
	}
	if raw, err := privatefile.Read(filepath.Join(dir, "release-root-checkpoint.json"), 4096); err == nil {
		var previous releaseRootCheckpoint
		if serverpool.DecodeStrict(raw, &previous) != nil || protocol.RequireJSONFields(raw, "version", "digest", "issued_at") != nil || previous.Version < 1 || !serverpool.ValidID(previous.Digest) || previous.IssuedAt < 1 || previous.IssuedAt > time.Now().Unix()+300 {
			return errors.New("release-root high-water state corrupt; explicit reviewed recovery required")
		}
		if err := check(previous.Version, previous.Digest); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, channel := range []string{"stable", "candidate", "canary"} {
		previous, err := readBundleCheckpoint(filepath.Join(dir, "release-bundle-checkpoint-"+channel+".json"), channel)
		if err != nil {
			return err
		}
		if previous.Sequence > 0 {
			if err := check(previous.RootVersion, previous.RootDigest); err != nil {
				return err
			}
		}
	}
	return nil
}

// ImportReleaseRoot is a local explicit ceremony; the updater never follows a
// release-feed instruction to erase roots or automatically trust a new key.
func ImportReleaseRoot(raw []byte) error {
	freshnessMu.Lock()
	defer freshnessMu.Unlock()
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	unlock, err := privatefile.TryLock(filepath.Join(store.Dir, "release-trust.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	root, err := activeReleaseRoot()
	if err != nil {
		return err
	}
	nextRoot, err := protocol.VerifyRootRotation(raw, root, time.Now())
	if err != nil {
		return err
	}
	path := filepath.Join(store.Dir, "release-root-chain.json")
	var chain []protocol.RootRotation
	if old, err := privatefile.Read(path, 256<<10); err == nil {
		if serverpool.DecodeStrict(old, &chain) != nil {
			return errors.New("stored root chain corrupt")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(chain) >= 8 {
		return errors.New("root rotation chain capacity reached; reviewed migration required")
	}
	var rotation protocol.RootRotation
	if serverpool.DecodeStrict(raw, &rotation) != nil {
		return errors.New("invalid root rotation")
	}
	chain = append(chain, rotation)
	encoded, err := json.Marshal(chain)
	if err != nil {
		return err
	}
	// High-water is persisted BEFORE replacing the chain. A crash/write failure
	// may require explicit recovery, but cannot silently re-enable a retired key.
	digest, err := nextRoot.Digest()
	if err != nil {
		return err
	}
	checkpoint, err := json.Marshal(releaseRootCheckpoint{Version: nextRoot.Version, Digest: digest, IssuedAt: nextRoot.IssuedAt})
	if err != nil {
		return err
	}
	if err := privatefile.Write(filepath.Join(store.Dir, "release-root-checkpoint.json"), checkpoint); err != nil {
		return err
	}
	return privatefile.Write(path, encoded)
}

func releaseAsset(rel *Release, name string) (string, error) {
	var result string
	for _, asset := range rel.Assets {
		if asset.Name == name {
			if result != "" {
				return "", errors.New("duplicate signed release metadata")
			}
			result = asset.URL
		}
	}
	if result == "" || !validReleaseAssetURL(result, rel.TagName, name) {
		return "", fmt.Errorf("release lacks scoped %s", name)
	}
	return result, nil
}

func fetchSignedMetadata(ctx context.Context, cl *http.Client, rawURL string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", transport.BrowserUA)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("signed update metadata unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, errors.New("signed update metadata oversized or incomplete")
	}
	return raw, nil
}

func fetchReleaseBundle(ctx context.Context, cl *http.Client, rel *Release, channel string) (signedBundle, error) {
	root, err := activeReleaseRoot()
	if err != nil {
		return signedBundle{}, err
	}
	return fetchReleaseBundleWithRoot(ctx, cl, rel, channel, root)
}

// The normal updater always supplies its checked persisted root. A separate
// pure trust-input boundary lets synthetic fixtures exercise the actual HTTP
// metadata/parser/checkpoint path without reading or changing release keys.
func fetchReleaseBundleWithRoot(ctx context.Context, cl *http.Client, rel *Release, channel string, root protocol.ReleaseRoot) (signedBundle, error) {
	var result signedBundle
	manifestURL, err := releaseAsset(rel, protocol.ReleaseBundleName)
	if err != nil {
		return result, err
	}
	sigURL, err := releaseAsset(rel, protocol.ReleaseBundleSignature)
	if err != nil {
		return result, err
	}
	raw, err := fetchSignedMetadata(ctx, cl, manifestURL, protocol.MaxBundleBytes)
	if err != nil {
		return result, err
	}
	sigRaw, err := fetchSignedMetadata(ctx, cl, sigURL, 16<<10)
	if err != nil {
		return result, err
	}
	signatures, err := protocol.ParseBundleSignatures(sigRaw, root, true)
	if err != nil {
		return result, err
	}
	bundle, err := protocol.VerifyBundleWithRoot(raw, signatures, root, time.Now())
	if err != nil {
		return result, err
	}
	if bundle.Tag != rel.TagName || bundle.Channel != channel {
		return result, errors.New("signed release bundle tag/channel differs from explicit selection")
	}
	if err := checkBundleCompatibility(bundle, version.Version); err != nil {
		return result, err
	}
	if _, err := bundle.Artifact(windowsUpdateAsset(bundle.Tag), "windows/amd64"); err != nil {
		return result, err
	}
	if err := saveBundleCheckpointWithRoot(bundle, root); err != nil {
		return result, err
	}
	setUpdateStatus("signed channel metadata verified", bundle.Tag, bundle.ExpiresAt)
	return signedBundle{Bundle: bundle, Raw: raw}, nil
}

func saveBundleCheckpoint(bundle protocol.ReleaseBundle) error {
	root, err := activeReleaseRoot()
	if err != nil {
		return err
	}
	return saveBundleCheckpointWithRoot(bundle, root)
}

func checkBundleCompatibility(bundle protocol.ReleaseBundle, running string) error {
	if !strings.HasPrefix(running, "v") {
		running = "v" + running
	}
	ordering, err := protocol.CompareReleaseVersions(running, bundle.MinimumVersion)
	if err != nil || ordering < 0 {
		return errors.New("running client is below the signed compatibility minimum; explicit reviewed upgrade required")
	}
	return nil
}

func saveBundleCheckpointWithRoot(bundle protocol.ReleaseBundle, root protocol.ReleaseRoot) error {
	freshnessMu.Lock()
	defer freshnessMu.Unlock()
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	unlock, err := privatefile.TryLock(filepath.Join(store.Dir, "release-trust.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if bundle.Validate(time.Now()) != nil || root.Validate(time.Now()) != nil || bundle.RootVersion != root.Version {
		return errors.New("invalid signed checkpoint or root")
	}
	path := filepath.Join(store.Dir, "release-bundle-checkpoint-"+bundle.Channel+".json")
	digest, err := bundle.Digest()
	if err != nil {
		return err
	}
	if err := checkRootHighWater(store.Dir, root); err != nil {
		return err
	}
	rootDigest, err := root.Digest()
	if err != nil {
		return err
	}
	previous, err := readBundleCheckpoint(path, bundle.Channel)
	if err != nil {
		return err
	}
	if previous.Sequence > 0 && (bundle.Sequence < previous.Sequence || isNewer(bundle.Tag, previous.Tag) || bundle.IssuedAt < previous.IssuedAt || (bundle.Sequence == previous.Sequence && digest != previous.Digest)) {
		return errors.New("signed bundle rollback/conflicting sequence refused")
	}
	raw, err := json.Marshal(bundleCheckpoint{Channel: bundle.Channel, Sequence: bundle.Sequence, Tag: bundle.Tag, Digest: digest, IssuedAt: bundle.IssuedAt, ExpiresAt: bundle.ExpiresAt, RootVersion: root.Version, RootDigest: rootDigest})
	if err != nil {
		return err
	}
	return privatefile.Write(path, raw)
}

func rolloutAllowed(bundle protocol.ReleaseBundle, cohort string) bool {
	if bundle.RolloutPercent == 100 {
		return true
	}
	if bundle.RolloutPercent == 0 || cohort == "" {
		return false
	}
	sum := sha256.Sum256([]byte("otu-rollout-v1\x00" + bundle.Channel + "\x00" + cohort))
	return int(binary.BigEndian.Uint32(sum[:4])%100) < bundle.RolloutPercent
}

func updateCohort() (string, error) {
	store, err := NewTokenStore()
	if err != nil {
		return "", err
	}
	path := filepath.Join(store.Dir, "update-cohort.json")
	var value struct {
		ID string `json:"id"`
	}
	if raw, err := privatefile.Read(path, 256); err == nil {
		if serverpool.DecodeStrict(raw, &value) != nil || len(value.ID) != 43 {
			return "", errors.New("update cohort corrupt")
		}
		return value.ID, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	value.ID = base64.RawURLEncoding.EncodeToString(nonce[:])
	raw, _ := json.Marshal(value)
	if err := privatefile.WriteNew(path, raw); err != nil {
		if os.IsExist(err) {
			stored, readErr := privatefile.Read(path, 256)
			if readErr == nil && serverpool.DecodeStrict(stored, &value) == nil && len(value.ID) == 43 {
				return value.ID, nil
			}
		}
		return "", err
	}
	return value.ID, nil // distinct from every operator's device token/fingerprint
}

func CheckUpdateChannel(ctx context.Context, socksAddr, channel string) (result *Release, retErr error) {
	if version.LocalPreview != "" {
		setUpdateStatus("unreleased local preview; automatic updates disabled", "", 0)
		return nil, errors.New("local preview cannot claim release freshness or authorize an install")
	}
	defer func() {
		if retErr != nil {
			setUpdateStatus("check unavailable or unverified; no install authorized", "", 0)
		}
	}()
	if channel == "" {
		channel = "stable"
	}
	if !protocol.ValidUpdateChannel(channel) {
		return nil, errors.New("invalid explicit update channel")
	}
	// Validate trust even when unsigned discovery returns no matching label.
	if _, err := activeReleaseRoot(); err != nil {
		return nil, err
	}
	var rel *Release
	var err error
	if channel == "stable" {
		rel, err = LatestRelease(ctx, socksAddr)
	} else {
		rel, err = channelRelease(ctx, socksAddr, channel)
	}
	if err != nil {
		return nil, err
	}
	if rel == nil {
		return nil, errors.New("release channel discovery has no signed target; freshness unknown, not verified up-to-date")
	}
	if rel.Draft || (channel == "stable" && rel.Prerelease) {
		return nil, errors.New("stable updates cannot install draft/prerelease discovery targets")
	}
	if _, _, _, ok := parseVersion(rel.TagName); !ok || !strings.HasPrefix(rel.TagName, "v") || belowMinTag(rel.TagName) {
		return nil, errors.New("invalid or below-floor release channel target")
	}
	if isNewer(rel.TagName, version.Version) {
		return nil, errors.New("release channel is older than the running version; implicit rollback refused")
	}
	cl := updateClient(socksAddr)
	defer cl.CloseIdleConnections()
	need := channel != "stable" || requiresReleaseBundle(rel.TagName)
	if !need {
		store, err := NewTokenStore()
		if err != nil {
			return nil, err
		}
		path := filepath.Join(store.Dir, "release-bundle-checkpoint-"+channel+".json")
		if _, err := privatefile.Read(path, 4096); err == nil {
			need = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	root, err := activeReleaseRoot()
	if err != nil {
		return nil, err
	}
	if root.Version > 1 {
		need = true
	}
	for _, asset := range rel.Assets {
		if asset.Name == protocol.ReleaseBundleName {
			need = true
		}
	}
	if need {
		bundle, err := fetchReleaseBundle(ctx, cl, rel, channel)
		if err != nil {
			return nil, err
		}
		cohort, err := updateCohort()
		if err != nil {
			return nil, err
		}
		if !rolloutAllowed(bundle.Bundle, cohort) {
			setUpdateStatus("outside signed staged rollout cohort", bundle.Bundle.Tag, bundle.Bundle.ExpiresAt)
			return nil, nil
		}
		rel.signedBundle = &bundle
		setUpdateStatus("signed update available", bundle.Bundle.Tag, bundle.Bundle.ExpiresAt)
	} else if channel == "stable" {
		if err := checkReleaseFreshness(ctx, cl, rel, version.Version); err != nil {
			return nil, err
		}
	}
	if isNewer(rel.TagName, version.Version) {
		return nil, errors.New("release channel is older than the running version; implicit rollback refused")
	}
	if !isNewer(version.Version, rel.TagName) {
		return nil, nil
	}
	return rel, nil
}

func channelRelease(ctx context.Context, socksAddr, channel string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+updateRepo+"/releases?per_page=50", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	cl := updateClient(socksAddr)
	defer cl.CloseIdleConnections()
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("release channel metadata unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 {
		return nil, errors.New("release channel feed oversized")
	}
	var releases []Release
	if json.Unmarshal(raw, &releases) != nil || len(releases) > 50 {
		return nil, errors.New("release channel feed invalid")
	}
	var newest *Release
	for i := range releases {
		r := &releases[i]
		if r.Draft || !r.Prerelease || !strings.HasPrefix(r.Name, "["+channel+"] ") {
			continue
		}
		if newest == nil || isNewer(newest.TagName, r.TagName) {
			newest = r
		}
	}
	return newest, nil // human label discovers a candidate; signed channel policy authorizes it
}
