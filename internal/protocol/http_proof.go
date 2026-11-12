package protocol

import (
	"crypto/sha256"
	"encoding/hex"
)

// HTTPProofMsg binds possession proof to the exact method, path, timestamp,
// nonce and request bytes. It cannot be replayed as a tunnel handshake.
func HTTPProofMsg(method, path, at, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte("otu-http-proof-v1\x00" + method + "\x00" + path + "\x00" + at + "\x00" + nonce + "\x00" + hex.EncodeToString(sum[:]))
}
