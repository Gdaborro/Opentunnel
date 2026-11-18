package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func syntheticBundle(now time.Time) ReleaseBundle {
	return ReleaseBundle{Version: 1, Tag: "v1.1.99", Channel: "candidate", Sequence: 10, RolloutPercent: 10, SourceCommit: strings.Repeat("a", 40), Toolchain: "go1.27.4", BuildRecipe: "otu-repro-v1", MinimumVersion: "v1.1.10", RootVersion: 1, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Artifacts: []ReleaseArtifact{{Name: "otu-client-windows-amd64.exe", Platform: "windows/amd64", SHA256: strings.Repeat("b", 64), Bytes: 4096}, {Name: "otu-server-linux-amd64", Platform: "linux/amd64", SHA256: strings.Repeat("c", 64), Bytes: 8192}}}
}

func TestReleaseBundleBindsAllArtifactsSourceChannelAndCohort(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	bundle := syntheticBundle(now)
	raw, _ := json.Marshal(bundle)
	sig := ed25519.Sign(key, ReleaseBundleMessage(raw))
	if _, err := VerifyReleaseBundle(raw, sig, pub, now); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*ReleaseBundle){func(b *ReleaseBundle) { b.Channel = "stable" }, func(b *ReleaseBundle) { b.RolloutPercent = 100 }, func(b *ReleaseBundle) { b.SourceCommit = strings.Repeat("d", 40) }, func(b *ReleaseBundle) { b.Artifacts[1].SHA256 = strings.Repeat("e", 64) }, func(b *ReleaseBundle) { b.Artifacts[0].Platform = "linux/amd64" }} {
		var altered ReleaseBundle
		_ = json.Unmarshal(raw, &altered)
		mutation(&altered)
		changed, _ := json.Marshal(altered)
		if _, err := VerifyReleaseBundle(changed, sig, pub, now); err == nil {
			t.Fatal("signed provenance/channel/artifact changed without signature")
		}
	}
	if _, err := VerifyReleaseBundle(raw, sig, pub, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired bundle accepted")
	}
	bundle.Artifacts = append(bundle.Artifacts, bundle.Artifacts[0])
	if bundle.Validate(now) == nil {
		t.Fatal("duplicate artifact accepted")
	}
}

func TestReleaseRootRotationNeedsOldAndNewDistinctThresholdSignatures(t *testing.T) {
	now := time.Now()
	oldPub, oldKey, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	old := ReleaseRoot{Version: 1, Keys: []string{base64.StdEncoding.EncodeToString(oldPub)}, Threshold: 1, IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	newRoot := ReleaseRoot{Version: 2, Keys: []string{base64.StdEncoding.EncodeToString(newPub)}, Threshold: 1, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	msg, _ := ReleaseRootMessage(newRoot)
	rotation := RootRotation{Root: newRoot, Signatures: []RootSignature{{KeyID: ReleaseKeyID(newPub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(newKey, msg))}}}
	raw, _ := json.Marshal(rotation)
	if _, err := VerifyRootRotation(raw, old, now); err == nil {
		t.Fatal("new key self-authorized a rotation")
	}
	rotation.Signatures = append(rotation.Signatures, RootSignature{KeyID: ReleaseKeyID(oldPub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(oldKey, msg))})
	raw, _ = json.Marshal(rotation)
	if _, err := VerifyRootRotation(raw, old, now); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRootRotation(raw, newRoot, now); err == nil {
		t.Fatal("root replay was accepted as another rotation")
	}
	bundle := syntheticBundle(now)
	bundle.RootVersion = 2
	raw, _ = json.Marshal(bundle)
	sigs := []RootSignature{{KeyID: ReleaseKeyID(oldPub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(oldKey, ReleaseBundleMessage(raw)))}}
	if _, err := VerifyBundleWithRoot(raw, sigs, newRoot, now); err == nil {
		t.Fatal("retired signing key still authorized a release")
	}
	sigs = []RootSignature{{KeyID: ReleaseKeyID(newPub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(newKey, ReleaseBundleMessage(raw)))}}
	if _, err := VerifyBundleWithRoot(raw, sigs, newRoot, now); err != nil {
		t.Fatal(err)
	}
}
