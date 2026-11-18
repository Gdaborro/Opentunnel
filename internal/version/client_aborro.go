//go:build !genericclient

package version

// Preserve the released fleet's identity and configuration directory. Public
// generic builds use the separate compile-time genericclient edition instead.
const ClientEdition = "aborro"
const RequiresOwnServerConfiguration = false

// Released v1.1.10 clients already request this name. Keep it bound to the
// hosted edition so their update never silently adopts the generic identity.
const ClientWindowsUpdateAsset = "otu-client-windows-amd64.exe"
const ClientBanRegistryKey = `Software\OpenTunnel`

var ProductName = "opentunnel"
