//go:build genericclient

package version

// Generic clients never bootstrap into the original operator's server or reuse
// its default device credentials. Signed imported profiles remain per-operator.
const ClientEdition = "generic"
const RequiresOwnServerConfiguration = true
const ClientWindowsUpdateAsset = "otu-client-generic-windows-amd64.exe"
const ClientBanRegistryKey = `Software\OpenTunnelGeneric`

var ProductName = "opentunnel-generic"
