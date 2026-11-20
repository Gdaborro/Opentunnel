package main

import (
	"strings"
	"testing"

	"opentunnel/internal/version"
)

func TestClientVersionTextUsesCanonicalReleaseTag(t *testing.T) {
	previous := version.Version
	defer func() { version.Version = previous }()
	version.Version = "1.1.11"
	if got := clientVersionText(); got != "opentunnel client v1.1.11" {
		t.Fatalf("client version output = %q", got)
	}
	version.LocalPreview = "synthetic"
	defer func() { version.LocalPreview = "" }()
	if got := clientVersionText(); !strings.Contains(got, "UNRELEASED local preview") {
		t.Fatalf("local preview was not explicit: %q", got)
	}
}
