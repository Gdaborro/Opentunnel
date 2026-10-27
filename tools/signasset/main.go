// signasset signs a release asset with the project's Ed25519 release key
// and writes <file>.sig (base64 signature). genkey mode creates a new
// keypair when the key file is missing.
//
// Usage:
//
//	go run ./tools/signasset -gen -key release.ed25519        # create keypair
//	go run ./tools/signasset -key release.ed25519 otu-client-windows-amd64.exe
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func main() {
	gen := flag.Bool("gen", false, "generate a new keypair at -key (refuses to overwrite)")
	manifest := flag.Bool("manifest", false, "sign a release manifest (requires -tag): binds the tag to the asset hash")
	tag := flag.String("tag", "", "release tag, e.g. v0.9.27 (with -manifest)")
	keyPath := flag.String("key", "release.ed25519", "private key path (raw 64-byte seed+pub)")
	flag.Parse()

	if *gen {
		if _, err := os.Stat(*keyPath); err == nil {
			fmt.Fprintln(os.Stderr, "refusing to overwrite existing key")
			os.Exit(1)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(*keyPath, priv, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("private key: %s (KEEP OFFLINE, NEVER COMMIT)\n", *keyPath)
		fmt.Printf("public  key (embed in internal/client/updatekey.go):\n%s\n", base64.StdEncoding.EncodeToString(pub))
		return
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: signasset -key <keyfile> <asset>")
		os.Exit(1)
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(raw) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "bad key size %d (want %d)\n", len(raw), ed25519.PrivateKeySize)
		os.Exit(1)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var msg []byte
	var out string
	if *manifest {
		if *tag == "" {
			fmt.Fprintln(os.Stderr, "-manifest requires -tag")
			os.Exit(1)
		}
		sum := sha256.Sum256(data)
		// MUST match internal/client.ReleaseMsg byte for byte.
		msg = []byte("otu-release:" + *tag + ":" + hex.EncodeToString(sum[:]))
		out = "manifest.sig"
	} else {
		// Legacy bare-file signature: still produced for every release so
		// pre-0.9.27 clients (which verify file bytes only) keep updating.
		msg = data
		out = flag.Arg(0) + ".sig"
	}
	sig := ed25519.Sign(ed25519.PrivateKey(raw), msg)
	if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("signed %s -> %s (%s)\n", flag.Arg(0), out, map[bool]string{true: "manifest", false: "bare"}[*manifest])
}
