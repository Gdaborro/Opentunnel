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
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	gen := flag.Bool("gen", false, "generate a new keypair at -key (refuses to overwrite)")
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
	sig := ed25519.Sign(ed25519.PrivateKey(raw), data)
	out := flag.Arg(0) + ".sig"
	if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("signed %s -> %s\n", flag.Arg(0), out)
}
