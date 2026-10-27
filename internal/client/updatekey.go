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

// MinUpdateTag is the minimum release tag this client will install, even
// if a valid signature covers it. It blocks tag-forgery downgrades: a
// middleman serving a genuinely-signed OLD release under its real tag is
// refused once the floor passes it. Raise this floor whenever a release
// fixes a security defect the fleet must not be rolled back below
// (audit round three, N-3; manifest verification itself landed in the
// floor version).
const MinUpdateTag = "v0.9.27"

// ReleaseMsg builds the exact bytes a release manifest signature covers:
// the tag and the asset hash are bound together, so a signature for one
// (tag, binary) pair can never authorize another.
func ReleaseMsg(tag, sha256hex string) []byte {
	return []byte("otu-release:" + tag + ":" + sha256hex)
}
