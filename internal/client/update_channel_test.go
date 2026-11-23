package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

type bundleHTTPFixture func(*http.Request) (*http.Response, error)

func (fn bundleHTTPFixture) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestSignedBundleActualFetchPathRejectsChannelTamperAndRollback(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	root := protocol.ReleaseRoot{Version: 1, Keys: []string{base64.StdEncoding.EncodeToString(pub)}, Threshold: 1, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	b := protocol.ReleaseBundle{Version: 1, Tag: "v1.1.99", Channel: "candidate", Sequence: 5, RolloutPercent: 10, SourceCommit: strings.Repeat("a", 40), Toolchain: "go1.27.4", BuildRecipe: "otu-repro-v1", MinimumVersion: "v1.1.10", RootVersion: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Artifacts: []protocol.ReleaseArtifact{{Name: updateAssetWin, Platform: "windows/amd64", SHA256: strings.Repeat("b", 64), Bytes: 4096}}}
	raw, _ := json.Marshal(b)
	sign := func(data []byte) []byte {
		signatures := []protocol.RootSignature{{KeyID: protocol.ReleaseKeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.ReleaseBundleMessage(data)))}}
		encoded, _ := json.Marshal(signatures)
		return encoded
	}
	sig := sign(raw)
	rel := &Release{TagName: b.Tag}
	for _, name := range []string{protocol.ReleaseBundleName, protocol.ReleaseBundleSignature} {
		rel.Assets = append(rel.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		}{Name: name, URL: "https://github.com/" + updateRepo + "/releases/download/" + b.Tag + "/" + name})
	}
	hc := &http.Client{Transport: bundleHTTPFixture(func(req *http.Request) (*http.Response, error) {
		data := raw
		if strings.HasSuffix(req.URL.Path, ".sig") {
			data = sig
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}, nil
	})}
	if _, err := fetchReleaseBundleWithRoot(context.Background(), hc, rel, "candidate", root); err != nil {
		t.Fatal("signed fixture metadata path failed", err)
	}
	if _, err := fetchReleaseBundleWithRoot(t.Context(), hc, rel, "stable", root); err == nil {
		t.Fatal("intercepted channel label authorized candidate on stable")
	}
	b.RolloutPercent = 100
	raw, _ = json.Marshal(b) // keep old signature
	if _, err := fetchReleaseBundleWithRoot(t.Context(), hc, rel, "candidate", root); err == nil {
		t.Fatal("tampered rollout metadata accepted")
	}
	b.Sequence = 4
	raw, _ = json.Marshal(b)
	sig = sign(raw)
	if _, err := fetchReleaseBundleWithRoot(t.Context(), hc, rel, "candidate", root); err == nil {
		t.Fatal("signed old sequence rolled back actual fetch checkpoint")
	}
}

func TestSignedChannelCheckpointRejectsReplaysAndConflictingSequence(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	now := time.Now()
	b := protocol.ReleaseBundle{Version: 1, Channel: "candidate", Sequence: 1, Tag: "v1.1.99", SourceCommit: strings.Repeat("a", 40), Toolchain: "go1.27.4", BuildRecipe: "otu-repro-v1", MinimumVersion: "v1.1.10", RootVersion: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Artifacts: []protocol.ReleaseArtifact{{Name: updateAssetWin, Platform: "windows/amd64", SHA256: strings.Repeat("b", 64), Bytes: 4096}}}
	if err := saveBundleCheckpoint(b); err != nil {
		t.Fatal(err)
	}
	old := b
	old.Sequence = 0
	if err := saveBundleCheckpoint(old); err == nil {
		t.Fatal("sequence rollback accepted")
	}
	old = b
	old.RolloutPercent = 100
	if err := saveBundleCheckpoint(old); err == nil {
		t.Fatal("same sequence changed staged cohort")
	}
	b.Sequence = 2
	b.Channel = "stable"
	if err := saveBundleCheckpoint(b); err != nil {
		t.Fatal("independent channel checkpoint interfered", err)
	}
	store, _ := NewTokenStore()
	path := filepath.Join(store.Dir, "release-bundle-checkpoint-stable.json")
	if err := os.WriteFile(path, []byte(`{"channel":"stable","sequence":999,"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveBundleCheckpoint(b); err == nil {
		t.Fatal("malformed checkpoint reset freshness")
	}
}

func TestSignedRolloutCohortIsStableAndMonotonic(t *testing.T) {
	b := protocol.ReleaseBundle{Channel: "canary", RolloutPercent: 0}
	if rolloutAllowed(b, "cohort") {
		t.Fatal("zero rollout installed")
	}
	b.RolloutPercent = 100
	if !rolloutAllowed(b, "cohort") {
		t.Fatal("full rollout excluded device")
	}
	for i := range 100 {
		cohort := strings.Repeat("x", i+1)
		b.RolloutPercent = 10
		first := rolloutAllowed(b, cohort)
		b.Sequence++
		if first != rolloutAllowed(b, cohort) {
			t.Fatal("sequence rerolled device cohort")
		}
		b.RolloutPercent = 50
		if first && !rolloutAllowed(b, cohort) {
			t.Fatal("wider cohort removed selected device")
		}
	}
	if !requiresReleaseBundle("v1.1.99") || requiresReleaseBundle("v1.1.10") {
		t.Fatal("legacy ceiling permits new unsigned artifact bundle or breaks released compatibility")
	}
}

func TestCorruptRotatedRootCannotFallBackToEmbeddedKey(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, _ := NewTokenStore()
	if err := os.WriteFile(filepath.Join(store.Dir, "release-root-chain.json"), []byte(`null`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := activeReleaseRoot(); err == nil {
		t.Fatal("corrupt root chain silently reverted to embedded trust")
	}
}

func TestEmbeddedReleaseRootHasValidBoundedLifetime(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	root, err := activeReleaseRoot()
	if err != nil {
		t.Fatal("default stable update trust is invalid", err)
	}
	if root.Version != 1 || len(root.Keys) != 1 || root.Keys[0] != ReleasePubKey {
		t.Fatal("released signing trust changed")
	}
}
