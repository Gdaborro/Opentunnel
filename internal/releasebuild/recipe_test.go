package releasebuild

import (
	"strings"
	"testing"

	"opentunnel/internal/protocol"
)

func TestFixedRecipeContainsBothClientEditionsAndEveryRequiredExecutable(t *testing.T) {
	seen := map[string]Target{}
	for _, target := range RecipeTargets() {
		if _, exists := seen[target.Name]; exists {
			t.Fatal("duplicate fixed recipe target")
		}
		seen[target.Name] = target
		platform, _, allowed := protocol.ReleaseArtifactPolicy(target.Name)
		if !allowed || platform != target.Platform {
			t.Fatal("build recipe role differs from signed inventory")
		}
		args, err := BuildArguments("v1.1.99", "/synthetic/output", target)
		if err != nil || !strings.Contains(strings.Join(args, " "), "-buildvcs=true") {
			t.Fatal("fixed recipe lost source identity", err)
		}
	}
	for _, name := range protocol.RequiredReleaseArtifacts() {
		platform, _, _ := protocol.ReleaseArtifactPolicy(name)
		if strings.Contains(platform, "/") {
			if _, found := seen[name]; !found {
				t.Fatal("build recipe is missing a coordinated binary", name)
			}
		}
	}
	if seen["otu-client-windows-amd64.exe"].Tags != "" || seen["otu-client-generic-windows-amd64.exe"].Tags != "genericclient" || seen["otu-client-linux-amd64"].Tags != "genericclient" {
		t.Fatal("recipe crossed client edition defaults")
	}
	if _, err := BuildArguments("v1.1.99", "/synthetic", Target{Name: "caller-selected", Package: "./unreviewed"}); err == nil {
		t.Fatal("caller-selected package accepted")
	}
}
