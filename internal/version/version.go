// Package version carries the release version for both binaries, stamped at
// build time via -ldflags "-X opentunnel/internal/version.Version=vX.Y.Z".
package version

// Version defaults to the next planned release; release builds stamp the tag.
var Version = "0.9.24"

// ProductName, ProcessID and StopHelper name the install surface: the
// %LOCALAPPDATA% data dir, the process image (no .exe), and the generated
// stop helper. Defaults keep today's layout; a redeployed build can override
// all three at build time via
//
//	-ldflags "-X opentunnel/internal/version.ProductName=X -X opentunnel/internal/version.ProcessID=Y -X opentunnel/internal/version.StopHelper=Z"
//
// so no "opentunnel"/"otu-client" strings remain on the target machine.
var (
	ProductName = "opentunnel"
	ProcessID   = "otu-client"
	StopHelper  = "stop-otu.bat"
)
