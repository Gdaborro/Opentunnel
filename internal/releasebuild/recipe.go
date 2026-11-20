package releasebuild

import (
	"errors"
	"strings"

	"opentunnel/internal/protocol"
)

type Target struct {
	Name      string
	Platform  string
	Package   string
	Directory string
	Tags      string
	Companion bool
}

// RecipeTargets is the fixed coordinated distribution, not caller-controlled
// package paths or tool arguments. Release upload/root envelopes remain separate.
func RecipeTargets() []Target {
	var targets []Target
	for _, product := range []string{"client", "server", "panel", "pool", "migrate", "reality", "xray"} {
		platforms := []string{"windows/amd64", "linux/amd64", "linux/arm64"}
		if product == "client" {
			platforms = []string{"windows/amd64", "linux/amd64"}
		}
		for _, platform := range platforms {
			name := "otu-" + product + "-" + strings.ReplaceAll(platform, "/", "-")
			if platform == "windows/amd64" {
				name += ".exe"
			}
			target := Target{Name: name, Platform: platform, Package: "./cmd/otu-" + product}
			if product == "client" && strings.HasPrefix(platform, "linux/") {
				target.Tags = "genericclient"
			}
			if product == "xray" {
				target.Package, target.Directory, target.Companion = ".", "companions/xray", true
			}
			targets = append(targets, target)
		}
	}
	targets = append(targets, Target{Name: "otu-client-generic-windows-amd64.exe", Platform: "windows/amd64", Package: "./cmd/otu-client", Tags: "genericclient"})
	return targets
}

func BuildArguments(tag, output string, target Target) ([]string, error) {
	known := false
	for _, expected := range RecipeTargets() {
		known = known || expected == target
	}
	if !known {
		return nil, errors.New("target is not in the fixed release build recipe")
	}
	flags, err := LinkerFlags(tag, target.Companion)
	if err != nil {
		return nil, err
	}
	if !protocol.ValidReleaseTag(tag) || output == "" {
		return nil, errors.New("release build needs a canonical tag and explicit output")
	}
	args := []string{"build", "-mod=readonly", "-buildvcs=true", "-trimpath", "-pgo=off", "-ldflags=" + flags, "-o", output}
	if target.Tags != "" {
		args = append(args, "-tags="+target.Tags)
	}
	return append(args, target.Package), nil
}
