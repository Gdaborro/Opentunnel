// Package version carries the release version for both binaries, stamped at
// build time via -ldflags "-X opentunnel/internal/version.Version=X.Y.Z".
// Canonical release tags keep the v prefix; this display value does not.
package version

// Version defaults to the next planned release; release builds stamp the tag.
var Version = "1.1.13"

// LocalPreview identifies an explicitly unreleased development package. Signed
// release builds leave this empty; previews cannot authorize automatic updates.
var LocalPreview string

// Both editions change the same user's Windows proxy. They must share its
// ownership lease/recovery journals without sharing any device credentials.
func NetworkStateName() string {
	if ClientEdition == "generic" {
		return "opentunnel"
	}
	return ProductName
}

// ProductName, ProcessID and StopHelper name the install surface: the
// %LOCALAPPDATA% data dir, the process image (no .exe), and the generated
// stop helper. Defaults keep today's layout; a redeployed build can override
// all three at build time via
//
//	-ldflags "-X opentunnel/internal/version.ProductName=X -X opentunnel/internal/version.ProcessID=Y -X opentunnel/internal/version.StopHelper=Z"
//
// so no "opentunnel"/"otu-client" strings remain on the target machine.
var (
	ProcessID  = "otu-client"
	StopHelper = "stop-otu.bat"
)
