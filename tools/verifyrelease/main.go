// verifyrelease independently checks the compatibility and freshness signatures
// for a bounded Windows client release. It never reads a private signing key.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/protocol"
)

func main() {
	dir := flag.String("directory", "", "private release asset directory")
	tag := flag.String("tag", "", "expected signed canonical tag")
	flag.Parse()
	if flag.NArg() != 0 || *dir == "" || *tag == "" {
		fmt.Fprintln(os.Stderr, "use -directory PATH -tag vX.Y.Z")
		os.Exit(2)
	}
	if err := verify(*dir, *tag); err != nil {
		fmt.Fprintln(os.Stderr, "release verification:", err)
		os.Exit(1)
	}
}

func bounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("oversized release verification input")
	}
	return data, nil
}

func verify(dir, tag string) error {
	pub, err := base64.StdEncoding.DecodeString(client.ReleasePubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid embedded signing key")
	}
	data, err := bounded(filepath.Join(dir, "otu-client-windows-amd64.exe"), 64<<20)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	readSig := func(name string) ([]byte, error) {
		raw, err := bounded(filepath.Join(dir, name), 1024)
		if err != nil {
			return nil, err
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, errors.New("invalid signature encoding")
		}
		return sig, nil
	}
	bare, err := readSig("otu-client-windows-amd64.exe.sig")
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, data, bare) {
		return errors.New("legacy executable signature invalid")
	}
	manifest, err := readSig("manifest.sig")
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, client.ReleaseMsg(tag, digest), manifest) {
		return errors.New("tag/hash-bound signature invalid")
	}
	raw, err := bounded(filepath.Join(dir, protocol.FreshReleaseName), 16<<10)
	if err != nil {
		return err
	}
	freshSig, err := readSig(protocol.FreshReleaseSignature)
	if err != nil {
		return err
	}
	m, err := protocol.VerifyReleaseManifest(raw, freshSig, pub, time.Now())
	if err != nil {
		return err
	}
	if m.Tag != tag || m.Bytes != int64(len(data)) || !strings.EqualFold(m.SHA256, digest) {
		return errors.New("fresh signed target differs from requested tag/binary")
	}
	fmt.Printf("verified %s: legacy signature, tag/hash signature, freshness/platform/name/size; SHA256 %s\n", tag, digest)
	fmt.Printf("signed freshness expires: %s\n", time.Unix(m.ExpiresAt, 0).UTC().Format(time.RFC3339))
	return nil
}
