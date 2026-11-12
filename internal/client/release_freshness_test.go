package client

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

func TestSignedFeedCheckpointRejectsOlderVersionOrTime(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	m := protocol.ReleaseManifest{Tag: "v1.1.8", IssuedAt: time.Now().Unix(), SHA256: strings.Repeat("a", 64)}
	if err := saveReleaseCheckpoint(m); err != nil {
		t.Fatal(err)
	}
	old := m
	old.Tag = "v1.1.7"
	if err := saveReleaseCheckpoint(old); err == nil {
		t.Fatal("older signed target bypassed checkpoint")
	}
	old = m
	old.IssuedAt--
	if err := saveReleaseCheckpoint(old); err == nil {
		t.Fatal("older signed timestamp bypassed checkpoint")
	}
}

func TestInstalledTagCannotBypassRequiredFreshness(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	for _, tc := range []struct{ current, feed string }{
		{"v1.1.6", "v1.1.6"},
		{"v1.1.8", "v1.1.7"},
		{"v1.1.6", "v1.1.5"},
	} {
		if err := checkReleaseFreshness(context.Background(), http.DefaultClient, &Release{TagName: tc.feed}, tc.current); err == nil {
			t.Fatalf("feed %s bypassed freshness for installed %s", tc.feed, tc.current)
		}
	}
}

func TestSignedCheckpointCannotDowngradeToLegacyFeed(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if err := saveReleaseCheckpoint(protocol.ReleaseManifest{Tag: "v1.1.8", IssuedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := checkReleaseFreshness(t.Context(), http.DefaultClient, &Release{TagName: "v1.1.5"}, "v1.1.5"); err == nil {
		t.Fatal("legacy replay bypassed an observed signed target")
	}
}

func TestMalformedCheckpointDoesNotResetHighWaterMark(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Dir, "release-checkpoint.json")
	for _, data := range []string{
		`{"tag":"vnot-a-version","issued_at":1}`,
		`{"tag":"v1.1.8","issued_at":1,"unexpected":true}`,
		`{"tag":"v1.1.8","issued_at":1} {}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := saveReleaseCheckpoint(protocol.ReleaseManifest{Tag: "v1.1.9", IssuedAt: time.Now().Unix()}); err == nil {
			t.Fatal("malformed checkpoint was silently replaced")
		}
	}
}
