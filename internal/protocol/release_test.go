package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func TestReleaseFreshnessExpiryAndPlatformBinding(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m := ReleaseManifest{Version: 1, Tag: "v1.1.6", Platform: "windows/amd64", Asset: "otu-client-windows-amd64.exe", SHA256: strings.Repeat("a", 64), Bytes: 4096, IssuedAt: now.Unix() - 60, ExpiresAt: now.Add(time.Hour).Unix()}
	raw, _ := json.Marshal(m)
	sig := ed25519.Sign(key, ReleaseManifestMessage(raw))
	if _, err := VerifyReleaseManifest(raw, sig, pub, now); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseManifest(raw, sig, pub, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired signed release accepted")
	}
	m.Platform = "linux/amd64"
	changed, _ := json.Marshal(m)
	if _, err := VerifyReleaseManifest(changed, sig, pub, now); err == nil {
		t.Fatal("platform change bypassed signature")
	}
	m.Platform = "windows/amd64"
	m.ExpiresAt = now.Add(180 * 24 * time.Hour).Unix()
	changed, _ = json.Marshal(m)
	if _, err := VerifyReleaseManifest(changed, ed25519.Sign(key, ReleaseManifestMessage(changed)), pub, now); err == nil {
		t.Fatal("unbounded freshness window accepted")
	}
}

func TestReleaseFreshnessRejectsMissingAndOverflowingIssuance(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	base := ReleaseManifest{Version: 1, Tag: "v1.1.11", Platform: "windows/amd64", Asset: "otu-client-windows-amd64.exe", SHA256: strings.Repeat("a", 64), Bytes: 4096, IssuedAt: now.Unix() - 1, ExpiresAt: now.Add(time.Hour).Unix()}
	for _, tc := range []struct {
		name string
		edit func(*ReleaseManifest)
	}{
		{"zero", func(m *ReleaseManifest) { m.IssuedAt = 0 }},
		{"negative", func(m *ReleaseManifest) { m.IssuedAt = -1 }},
		{"overflow", func(m *ReleaseManifest) { m.IssuedAt = math.MinInt64; m.ExpiresAt = math.MaxInt64 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			tc.edit(&m)
			raw, _ := json.Marshal(m)
			if _, err := VerifyReleaseManifest(raw, ed25519.Sign(key, ReleaseManifestMessage(raw)), pub, now); err == nil {
				t.Fatal("malformed issuance window accepted")
			}
		})
	}
	var fields map[string]any
	raw, _ := json.Marshal(base)
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "issued_at")
	omitted, _ := json.Marshal(fields)
	if _, err := VerifyReleaseManifest(omitted, ed25519.Sign(key, ReleaseManifestMessage(omitted)), pub, now); err == nil {
		t.Fatal("omitted issuance time accepted")
	}
}

func FuzzSignedReleaseManifest(f *testing.F) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	valid, err := json.Marshal(ReleaseManifest{Version: 1, Tag: "v1.1.6", Platform: "windows/amd64", Asset: "otu-client-windows-amd64.exe", SHA256: strings.Repeat("a", 64), Bytes: 4096, IssuedAt: now.Unix() - 1, ExpiresAt: now.Unix() + 3600})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"issued_at":-9223372036854775808,"expires_at":9223372036854775807}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16<<10 {
			return
		}
		sig := ed25519.Sign(key, ReleaseManifestMessage(raw))
		_, _ = VerifyReleaseManifest(raw, sig, pub, now)
	})
}
