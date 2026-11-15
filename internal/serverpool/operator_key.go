package serverpool

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"opentunnel/internal/privatefile"
)

// GenerateOperatorKey creates a new dedicated profile-signing identity. It
// never replaces an existing key and is not the project's release-signing key.
func GenerateOperatorKey(path string) (string, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	defer clear(key)
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	defer clear(encoded)
	if err := privatefile.WriteNew(path, encoded); err != nil {
		return "", err
	}
	return OperatorID(pub), nil
}

func LoadOperatorKey(path string) (ed25519.PrivateKey, error) {
	raw, err := privatefile.Read(path, 4096)
	if err != nil {
		return nil, errors.New("operator profile-signing key unavailable")
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("operator key must be a dedicated PKCS8 Ed25519 private key")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("operator profile-signing key is invalid")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("operator profile-signing key must be Ed25519")
	}
	return key, nil
}

func Export(path string, p Profile, now time.Time) error {
	if err := p.Verify(now); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > MaxProfileSize {
		return errors.New("encoded profile exceeds size limit")
	}
	return privatefile.WriteNew(path, raw)
}
