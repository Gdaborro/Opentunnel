//go:build windows && netenvfixture

package client

// The fixture client must not read a machine identity or mutate the operator's
// real ban markers while testing proxy startup/cleanup. Production builds do
// not include this backend. The separate banBackend tests still inject their
// own stateful in-memory backend for policy behavior.
func deviceFingerprint() string { return "fixture-only-device-fingerprint" }

type fixtureBanBackend struct{}

func (fixtureBanBackend) Banned() bool         { return false }
func (fixtureBanBackend) Write(string, string) {}
func (fixtureBanBackend) Clear()               {}

var banState banBackend = fixtureBanBackend{}
