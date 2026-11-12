package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const FreshReleaseName = "release.json"
const FreshReleaseSignature = "release.json.sig"
const MaxReleaseValidity = 90 * 24 * time.Hour

var releaseVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ReleaseManifest is an offline signed, time-bounded release target. It limits
// replay/freeze duration and binds platform/name/size as well as version/hash.
// A censor can still block updates; expiry detects that loss of freshness, not
// force connectivity. Local clock correctness remains part of the trust model.
type ReleaseManifest struct {
	Version   int    `json:"version"`
	Tag       string `json:"tag"`
	Platform  string `json:"platform"`
	Asset     string `json:"asset"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func ReleaseManifestMessage(raw []byte) []byte {
	return append([]byte("otu-release-fresh-v1\x00"), raw...)
}

func VerifyReleaseManifest(raw, sig []byte, pub ed25519.PublicKey, now time.Time) (ReleaseManifest, error) {
	var m ReleaseManifest
	if len(raw) > 16<<10 || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, ReleaseManifestMessage(raw), sig) {
		return m, errors.New("fresh release signature invalid")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, errors.New("fresh release metadata invalid")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return m, errors.New("trailing release metadata")
	}
	if m.Version != 1 || !releaseVersionPattern.MatchString(m.Tag) || m.Platform != "windows/amd64" || m.Asset != "otu-client-windows-amd64.exe" || m.Bytes < 1024 || m.Bytes > 64<<20 {
		return m, errors.New("fresh release target is invalid")
	}
	if hash, err := hex.DecodeString(m.SHA256); err != nil || len(hash) != 32 {
		return m, errors.New("fresh release digest invalid")
	}
	if m.IssuedAt > now.Unix()+300 || m.ExpiresAt <= now.Unix() || m.ExpiresAt <= m.IssuedAt || m.ExpiresAt-m.IssuedAt > int64(MaxReleaseValidity/time.Second) {
		return m, errors.New("release metadata expired or outside its freshness window")
	}
	return m, nil
}
