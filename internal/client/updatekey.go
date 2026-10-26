// updatekey.go: the Ed25519 release-signing public key. Update assets are
// verified against it BEFORE the binary swap, so a hostile middlebox
// serving fake release metadata + a matching fake sha256 line (both ride
// the same interceptable channel) still cannot push code: the signature
// is the only trust anchor, baked into the binary at build time.
//
// Key ceremonies: private key lives offline (tools/signasset -gen to
// mint a new pair); rotating it requires shipping a client with the new
// public key and signing with both during the transition window.
package client

// ReleasePubKey is the base64 Ed25519 public key for release assets.
const ReleasePubKey = "XqEAMqVF/y1ZGrA0gID/cg+PZevHwDjEuYoLXnhkQfI="
