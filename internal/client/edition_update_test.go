package client

import (
	"context"
	"strings"
	"testing"

	"opentunnel/internal/version"
)

func TestUpdateTargetCannotCrossCompileTimeClientEdition(t *testing.T) {
	if got := windowsUpdateAsset("v1.1.99"); got != version.ClientWindowsUpdateAsset {
		t.Fatal("new signed bundle selected another edition", got)
	}
	if version.ClientEdition == "aborro" {
		if windowsUpdateAsset("v1.1.10") != "otu-client-windows-amd64.exe" {
			t.Fatal("released v1.1.10 compatibility asset changed")
		}
		if windowsUpdateAsset("v1.1.99") != windowsUpdateAsset("v1.1.10") {
			t.Fatal("released hosted clients were moved to another edition's asset")
		}
	} else if windowsUpdateAsset("v1.1.99") != "otu-client-generic-windows-amd64.exe" {
		t.Fatal("generic client selected the legacy hosted asset")
	}
}

func TestLocalPreviewCannotCheckFreshnessInstallOrStartAnUpdateLoop(t *testing.T) {
	before := version.LocalPreview
	version.LocalPreview = "synthetic-preview"
	t.Cleanup(func() { version.LocalPreview = before })
	if _, err := CheckUpdateChannel(t.Context(), "must-not-contact.invalid", "stable"); err == nil {
		t.Fatal("unsigned preview claimed signed release freshness")
	}
	if err := SelfUpdate(t.Context(), &Release{TagName: "v1.1.99"}, "must-not-contact.invalid"); err == nil {
		t.Fatal("unsigned preview attempted an installation")
	}
	RunUpdateLoopChannel(context.Background(), "must-not-contact.invalid", "stable", func() { t.Fatal("preview requested replacement") })
	if status := CurrentUpdateStatus(); !strings.Contains(status.State, "preview") || status.ExpiresAt != 0 {
		t.Fatal("preview displays verified release freshness", status)
	}
}
