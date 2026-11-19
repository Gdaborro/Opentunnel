package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"opentunnel/internal/serverpool"
)

const ReleaseRootName = "release-root.json"

type ReleaseRoot struct {
	Version   int64    `json:"version"`
	Keys      []string `json:"keys"` // base64 Ed25519 public keys only
	Threshold int      `json:"threshold"`
	IssuedAt  int64    `json:"issued_at"`
	ExpiresAt int64    `json:"expires_at"`
}
type RootSignature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
type RootRotation struct {
	Root       ReleaseRoot     `json:"root"`
	Signatures []RootSignature `json:"signatures"`
}

func ReleaseKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
func (root ReleaseRoot) Validate(now time.Time) error {
	if root.Version < 1 || len(root.Keys) < 1 || len(root.Keys) > 8 || root.Threshold < 1 || root.Threshold > len(root.Keys) || root.IssuedAt < 1 || root.IssuedAt > now.Unix()+300 || root.ExpiresAt <= now.Unix() || root.ExpiresAt <= root.IssuedAt || root.ExpiresAt-root.IssuedAt > int64((5*365*24*time.Hour)/time.Second) {
		return errors.New("invalid or expired release trust root")
	}
	seen := map[string]bool{}
	for _, key := range root.Keys {
		pub, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(pub) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(pub) != key || seen[key] {
			return errors.New("invalid or duplicate release trust key")
		}
		seen[key] = true
	}
	return nil
}
func ReleaseRootMessage(root ReleaseRoot) ([]byte, error) {
	raw, err := json.Marshal(root)
	return append([]byte("otu-release-root-v1\x00"), raw...), err
}

func (root ReleaseRoot) Digest() (string, error) {
	raw, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Both client and offline verifier accept the same bounded threshold envelope.
// Root-1 detached compatibility is explicit and never applies to rotated roots.
func ParseBundleSignatures(raw []byte, root ReleaseRoot, allowDetachedRoot1 bool) ([]RootSignature, error) {
	if len(raw) > 16<<10 {
		return nil, errors.New("bundle signature envelope oversized")
	}
	var signatures []RootSignature
	if serverpool.DecodeStrict(raw, &signatures) == nil {
		if len(signatures) < 1 || len(signatures) > 16 {
			return nil, errors.New("invalid signature envelope count")
		}
		for _, signature := range signatures {
			decoded, err := base64.StdEncoding.DecodeString(signature.Signature)
			if !serverpool.ValidID(signature.KeyID) || err != nil || len(decoded) != ed25519.SignatureSize {
				return nil, errors.New("invalid signature envelope member")
			}
		}
		return signatures, nil
	}
	if !allowDetachedRoot1 || root.Version != 1 || root.Threshold != 1 || len(root.Keys) != 1 {
		return nil, errors.New("invalid bundle signature envelope")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	pub, pubErr := base64.StdEncoding.DecodeString(root.Keys[0])
	if err != nil || pubErr != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid detached bundle signature")
	}
	return []RootSignature{{KeyID: ReleaseKeyID(pub), Signature: base64.StdEncoding.EncodeToString(sig)}}, nil
}

// Every rotation needs the old root's threshold AND the new root's threshold.
// Version increments exactly once; trust never falls back to the embedded root
// after observing a rotated root. Actual key ceremonies stay operator-owned.
func VerifyRootRotation(raw []byte, previous ReleaseRoot, now time.Time) (ReleaseRoot, error) {
	var rotation RootRotation
	if len(raw) > 32<<10 || serverpool.DecodeStrict(raw, &rotation) != nil {
		return ReleaseRoot{}, errors.New("invalid root rotation schema")
	}
	if rotation.Root.Version != previous.Version+1 || rotation.Root.IssuedAt < previous.IssuedAt || rotation.Root.Validate(now) != nil || len(rotation.Signatures) > 16 {
		return ReleaseRoot{}, errors.New("release root rollback or invalid validity window")
	}
	if err := previous.Validate(time.Unix(rotation.Root.IssuedAt, 0)); err != nil {
		return ReleaseRoot{}, errors.New("release root predecessor was invalid at rotation issuance")
	}
	msg, err := ReleaseRootMessage(rotation.Root)
	if err != nil {
		return ReleaseRoot{}, err
	}
	count := func(root ReleaseRoot) int {
		keys := map[string]ed25519.PublicKey{}
		for _, key := range root.Keys {
			pub, err := base64.StdEncoding.DecodeString(key)
			if err == nil && len(pub) == 32 {
				keys[ReleaseKeyID(pub)] = pub
			}
		}
		seen := map[string]bool{}
		for _, sig := range rotation.Signatures {
			pub, ok := keys[sig.KeyID]
			raw, err := base64.StdEncoding.DecodeString(sig.Signature)
			if ok && !seen[sig.KeyID] && err == nil && len(raw) == 64 && ed25519.Verify(pub, msg, raw) {
				seen[sig.KeyID] = true
			}
		}
		return len(seen)
	}
	if previous.Threshold < 1 || count(previous) < previous.Threshold || count(rotation.Root) < rotation.Root.Threshold {
		return ReleaseRoot{}, errors.New("release root needs old and new threshold signatures")
	}
	return rotation.Root, nil
}

func VerifyBundleWithRoot(raw []byte, signatures []RootSignature, root ReleaseRoot, now time.Time) (ReleaseBundle, error) {
	bundle, decodeErr := DecodeReleaseBundle(raw)
	if root.Validate(now) != nil || len(raw) > MaxBundleBytes || len(signatures) > 16 || decodeErr != nil || bundle.RootVersion != root.Version {
		return bundle, errors.New("release bundle trust root/schema mismatch")
	}
	seen := map[string]bool{}
	for _, key := range root.Keys {
		pub, _ := base64.StdEncoding.DecodeString(key)
		id := ReleaseKeyID(pub)
		for _, signature := range signatures {
			if signature.KeyID != id || seen[id] {
				continue
			}
			sig, err := base64.StdEncoding.DecodeString(signature.Signature)
			if err == nil && len(sig) == 64 && ed25519.Verify(pub, ReleaseBundleMessage(raw), sig) {
				seen[id] = true
			}
		}
	}
	if len(seen) < root.Threshold {
		return bundle, errors.New("release bundle threshold signature invalid")
	}
	return bundle, bundle.Validate(now)
}
