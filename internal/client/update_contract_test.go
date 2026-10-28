package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// TestBelowMinTagFloor: the embedded floor refuses signed-but-old
// releases (audit round three N-3 / round four downgrade class).
func TestBelowMinTagFloor(t *testing.T) {
	cases := []struct {
		tag  string
		want bool
	}{
		{"v0.9.26", true},
		{"0.9.26", true},
		{"v0.0.1", true},
		{"v0.9.27", false},
		{"v0.9.28", false},
		{"v1.0.0", false},
		{"garbage", true}, // unparseable → refuse
		{"", true},
	}
	for _, c := range cases {
		if got := belowMinTag(c.tag); got != c.want {
			t.Errorf("belowMinTag(%q) = %v, want %v", c.tag, got, c.want)
		}
	}
}

// TestReleaseMsgBinding: the manifest message binds tag and hash — a
// signature for one (tag,hash) pair must never validate another.
func TestReleaseMsgBinding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hash := strings.Repeat("ab", 32)
	sig := ed25519.Sign(priv, ReleaseMsg("v0.9.28", hash))

	if !ed25519.Verify(pub, ReleaseMsg("v0.9.28", hash), sig) {
		t.Fatal("signature must verify for the signed pair")
	}
	if ed25519.Verify(pub, ReleaseMsg("v9.9.9", hash), sig) {
		t.Fatal("forged tag must not verify")
	}
	if ed25519.Verify(pub, ReleaseMsg("v0.9.28", strings.Repeat("cd", 32)), sig) {
		t.Fatal("swapped asset hash must not verify")
	}
}

// TestSelfUpdateRefusesReleasesWithoutManifest: the download must not
// even start when manifest.sig is absent (unsigned/old release served by
// a middleman under a new tag).
func TestSelfUpdateRefusesReleasesWithoutManifest(t *testing.T) {
	rel := &Release{TagName: "v9.9.9"}
	rel.Assets = append(rel.Assets, struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	}{Name: "otu-client-windows-amd64.exe", URL: "https://invalid.example/x"})

	err := SelfUpdate(context.Background(), rel, "")
	if err == nil {
		t.Fatal("release without manifest.sig must be refused")
	}
	if !strings.Contains(err.Error(), "manifest") &&
		!strings.Contains(err.Error(), "minimum supported") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// TestSelfUpdateRefusesBelowFloor: a release older than MinUpdateTag is
// refused before any network activity.
func TestSelfUpdateRefusesBelowFloor(t *testing.T) {
	rel := &Release{TagName: "v0.9.20"}
	rel.Assets = append(rel.Assets,
		struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		}{Name: "otu-client-windows-amd64.exe", URL: "https://invalid.example/x"},
		struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		}{Name: "manifest.sig", URL: "https://invalid.example/sig"},
	)
	err := SelfUpdate(context.Background(), rel, "")
	if err == nil || !strings.Contains(err.Error(), "minimum supported") {
		t.Fatalf("below-floor release must be refused, got %v", err)
	}
}
