// Package version carries the release version for both binaries, stamped at
// build time via -ldflags "-X opentunnel/internal/version.Version=vX.Y.Z".
package version

// Version defaults to the next planned release; release builds stamp the tag.
var Version = "0.9.12"
