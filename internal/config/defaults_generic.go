//go:build genericclient

package config

// The generic executable cannot silently connect to the hosted fleet.
const DefaultClientTOML = GenericClientTOML
