package protocol

import (
	"errors"
	"strings"
)

const BuildProvenanceName = "BUILD-PROVENANCE.json"
const SourceArchiveName = "opentunnel-source.tar.gz"
const MaxReleaseInventoryBytes int64 = 768 << 20

// Publication helpers and the private broker must use this same narrow payload
// contract. Public signature/root envelopes are separate, not circular payloads.
func ReleaseArtifactPolicy(name string) (platform string, maximum int64, allowed bool) {
	if name == "otu-client-linux-arm64" {
		// The fixed recipe deliberately has no ARM64 client target. Do not let
		// a manually supplied executable bypass that reviewed build contract.
		return "", 0, false
	}
	if name == "otu-client-generic-windows-amd64.exe" {
		return "windows/amd64", 64 << 20, true
	}
	for _, product := range []string{"client", "server", "panel", "pool", "migrate", "reality", "xray"} {
		for _, target := range []string{"windows/amd64", "linux/amd64", "linux/arm64"} {
			filename := "otu-" + product + "-" + strings.ReplaceAll(target, "/", "-")
			if target == "windows/amd64" {
				filename += ".exe"
			}
			if filename == name {
				maximum = 64 << 20
				return target, maximum, true
			}
		}
	}
	switch name {
	case SourceArchiveName:
		return "source", 128 << 20, true
	case BuildProvenanceName:
		return "metadata", 256 << 10, true
	case "SBOM-otu-client.txt", "SBOM-otu-server.txt", "SBOM-otu-panel.txt":
		return "metadata", 2 << 20, true
	case "SOURCE-AND-LICENSE-NOTICE-XRAY.md":
		return "metadata", 256 << 10, true
	default:
		return "", 0, false
	}
}

func RequiredReleaseArtifacts() []string {
	return []string{
		"otu-client-windows-amd64.exe", "otu-client-generic-windows-amd64.exe", "otu-client-linux-amd64",
		"otu-server-linux-amd64", "otu-server-linux-arm64",
		"otu-panel-linux-amd64", "otu-panel-linux-arm64", "otu-migrate-linux-amd64",
		SourceArchiveName, BuildProvenanceName,
		"SBOM-otu-client.txt", "SBOM-otu-server.txt", "SBOM-otu-panel.txt",
	}
}

// This is inventory consistency, NOT evidence that a binary was built from the
// declared source. Authenticated independent reproducibility remains a gate.
func ValidateCoordinatedReleaseInventory(bundle ReleaseBundle) error {
	seen := map[string]bool{}
	var total int64
	xray := false
	for _, artifact := range bundle.Artifacts {
		platform, limit, allowed := ReleaseArtifactPolicy(artifact.Name)
		if !allowed || artifact.Platform != platform || seen[artifact.Name] || artifact.Bytes < 1 || artifact.Bytes > limit || artifact.Bytes > MaxReleaseInventoryBytes-total {
			return errors.New("release payload inventory has an unexpected name/platform/size or exceeds its aggregate bound")
		}
		seen[artifact.Name] = true
		total += artifact.Bytes
		xray = xray || strings.HasPrefix(artifact.Name, "otu-xray-")
	}
	for _, name := range RequiredReleaseArtifacts() {
		if !seen[name] {
			return errors.New("coordinated release inventory missing " + name)
		}
	}
	if xray && !seen["SOURCE-AND-LICENSE-NOTICE-XRAY.md"] {
		return errors.New("Xray payload requires source/license notice")
	}
	return nil
}

// Fixed public publication envelopes; allowlisting them is not verification of
// their contents or proof of reviewed source/artifact provenance.
func ReleaseEnvelopePolicy(name string) (int64, bool) {
	switch name {
	case ReleaseBundleName:
		return MaxBundleBytes, true
	case ReleaseBundleSignature:
		return 16 << 10, true
	case FreshReleaseName:
		return 16 << 10, true
	case FreshReleaseSignature, "manifest.sig", "otu-client-windows-amd64.exe.sig":
		return 1024, true
	case "release-root-chain.json":
		return 256 << 10, true
	default:
		return 0, false
	}
}
