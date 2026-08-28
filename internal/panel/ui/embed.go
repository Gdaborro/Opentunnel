// Package ui carries the built admin SPA (panel-ui/dist) so the server
// binary is fully self-contained. Refresh with scripts/build-panel.ps1.
package ui

import "embed"

//go:embed all:dist
var Dist embed.FS
