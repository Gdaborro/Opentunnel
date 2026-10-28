// verify manifest: exactly the v0.9.27 client's update verification.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"opentunnel/internal/client"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("read:", err)
		os.Exit(1)
	}
	sigRaw, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println("sig:", err)
		os.Exit(1)
	}
	tag := os.Args[3]
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		fmt.Println("bad sig file:", err)
		os.Exit(1)
	}
	pub, _ := base64.StdEncoding.DecodeString(client.ReleasePubKey)
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	ok := ed25519.Verify(ed25519.PublicKey(pub), client.ReleaseMsg(tag, got), sig)
	fmt.Printf("sha256: %s\nmanifest signature for %s: %v\n", got, tag, ok)
	if !ok {
		os.Exit(1)
	}
	// Negatives: wrong tag must fail; v0.9.26 below floor must be refused.
	wrongTag := client.ReleaseMsg("v9.9.9", got)
	fmt.Printf("forged-tag verify (want false): %v\n", ed25519.Verify(ed25519.PublicKey(pub), []byte(wrongTag), sig))
}
