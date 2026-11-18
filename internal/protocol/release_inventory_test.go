package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCoordinatedReleaseInventoryRequiresEveryPayloadAndExactPlatform(t *testing.T) {
	b := syntheticBundle(time.Now())
	b.Artifacts = nil
	for _, name := range RequiredReleaseArtifacts() {
		platform, _, ok := ReleaseArtifactPolicy(name)
		if !ok {
			t.Fatal(name)
		}
		b.Artifacts = append(b.Artifacts, ReleaseArtifact{Name: name, Platform: platform, SHA256: strings.Repeat("a", 64), Bytes: 4096})
	}
	if err := ValidateCoordinatedReleaseInventory(b); err != nil {
		t.Fatal(err)
	}
	for i := range b.Artifacts {
		bad := b
		bad.Artifacts = append([]ReleaseArtifact(nil), b.Artifacts...)
		bad.Artifacts = append(bad.Artifacts[:i:i], bad.Artifacts[i+1:]...)
		if ValidateCoordinatedReleaseInventory(bad) == nil {
			t.Fatal("missing coordinated artifact accepted", b.Artifacts[i].Name)
		}
	}
	bad := b
	bad.Artifacts = append([]ReleaseArtifact(nil), b.Artifacts...)
	bad.Artifacts[0].Platform = "linux/amd64"
	if ValidateCoordinatedReleaseInventory(bad) == nil {
		t.Fatal("artifact-name platform mismatch accepted")
	}
	bad = b
	bad.Artifacts = append(append([]ReleaseArtifact(nil), b.Artifacts...), ReleaseArtifact{Name: "README.txt", Platform: "metadata", Bytes: 1})
	if ValidateCoordinatedReleaseInventory(bad) == nil {
		t.Fatal("unreviewed extra payload accepted")
	}
}

func TestReleaseBundleRequiresExplicitSignedZeroFieldsAndCheckedVersionOrder(t *testing.T) {
	b := syntheticBundle(time.Now())
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rollout_percent", "issued_at", "root_version", "minimum_version"} {
		copy := map[string]json.RawMessage{}
		for k, v := range fields {
			if k != name {
				copy[k] = v
			}
		}
		omitted, _ := json.Marshal(copy)
		if _, err := DecodeReleaseBundle(omitted); err == nil {
			t.Fatal("omitted signed field accepted", name)
		}
	}
	b.MinimumVersion = "v1.1.100"
	if b.Validate(time.Now()) == nil {
		t.Fatal("minimum above target accepted")
	}
	if _, err := CompareReleaseVersions("v999999999999999999999.0.0", "v1.1.10"); err == nil {
		t.Fatal("overflow treated as a comparable version")
	}
	if order, err := CompareReleaseVersions("v1.1.10", "v1.1.99"); err != nil || order != -1 {
		t.Fatal(order, err)
	}
}
