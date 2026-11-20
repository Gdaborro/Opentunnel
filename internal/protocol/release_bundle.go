package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"opentunnel/internal/serverpool"
)

const ReleaseBundleName = "release-bundle.json"
const ReleaseBundleSignature = "release-bundle.json.sig"
const MaxBundleBytes = 256 << 10

type ReleaseArtifact struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
}

// An offline signature binds every artifact, build source/toolchain, channel,
// staged cohort and compatibility floor. A GitHub release label is discovery,
// never authorization to switch channels or replace a different artifact.
type ReleaseBundle struct {
	Version        int               `json:"version"`
	Tag            string            `json:"tag"`
	Channel        string            `json:"channel"`
	Sequence       int64             `json:"sequence"`
	RolloutPercent int               `json:"rollout_percent"`
	SourceCommit   string            `json:"source_commit"`
	Toolchain      string            `json:"toolchain"`
	BuildRecipe    string            `json:"build_recipe"`
	MinimumVersion string            `json:"minimum_version"`
	RootVersion    int64             `json:"root_version"`
	IssuedAt       int64             `json:"issued_at"`
	ExpiresAt      int64             `json:"expires_at"`
	Artifacts      []ReleaseArtifact `json:"artifacts"`
}

func ReleaseBundleMessage(raw []byte) []byte {
	return append([]byte("otu-release-bundle-v1\x00"), raw...)
}
func ValidUpdateChannel(channel string) bool {
	return channel == "stable" || channel == "canary" || channel == "candidate"
}

var artifactNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var sourceCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var toolchainPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)

func (b ReleaseBundle) Validate(now time.Time) error {
	if b.Version != 1 || !ValidReleaseTag(b.Tag) || !ValidUpdateChannel(b.Channel) || b.Sequence < 1 || b.RootVersion < 1 || b.RolloutPercent < 0 || b.RolloutPercent > 100 || !sourceCommitPattern.MatchString(b.SourceCommit) || !toolchainPattern.MatchString(b.Toolchain) || b.BuildRecipe != "otu-repro-v1" || !ValidReleaseTag(b.MinimumVersion) {
		return errors.New("invalid release bundle provenance/channel policy")
	}
	if ordering, err := CompareReleaseVersions(b.MinimumVersion, b.Tag); err != nil || ordering > 0 {
		return errors.New("release bundle compatibility minimum is newer than its target")
	}
	if b.IssuedAt < 1 || b.IssuedAt > now.Unix()+300 || b.ExpiresAt <= now.Unix() || b.ExpiresAt <= b.IssuedAt || b.ExpiresAt-b.IssuedAt > int64(MaxReleaseValidity/time.Second) {
		return errors.New("release bundle expired or outside its validity window")
	}
	if len(b.Artifacts) < 1 || len(b.Artifacts) > 64 {
		return errors.New("release bundle artifact inventory out of bounds")
	}
	seen := map[string]bool{}
	for _, a := range b.Artifacts {
		if !artifactNamePattern.MatchString(a.Name) || seen[a.Name] || a.Bytes < 1 || a.Bytes > 256<<20 || !serverpool.ValidID(a.SHA256) {
			return errors.New("invalid release bundle artifact")
		}
		switch a.Platform {
		case "windows/amd64", "linux/amd64", "linux/arm64", "source", "metadata":
		default:
			return errors.New("unsupported release artifact platform")
		}
		seen[a.Name] = true
	}
	return nil
}

func VerifyReleaseBundle(raw, sig []byte, pub ed25519.PublicKey, now time.Time) (ReleaseBundle, error) {
	var bundle ReleaseBundle
	if len(raw) > MaxBundleBytes || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, ReleaseBundleMessage(raw), sig) {
		return bundle, errors.New("release bundle signature invalid")
	}
	var err error
	if bundle, err = DecodeReleaseBundle(raw); err != nil {
		return bundle, err
	}
	return bundle, bundle.Validate(now)
}

func (b ReleaseBundle) Artifact(name, platform string) (ReleaseArtifact, error) {
	for _, a := range b.Artifacts {
		if a.Name == name && a.Platform == platform {
			return a, nil
		}
	}
	return ReleaseArtifact{}, errors.New("artifact absent from signed bundle")
}
func (b ReleaseBundle) Digest() (string, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
