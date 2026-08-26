package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreateCert returns a TLS certificate, generating and persisting a
// self-signed ECDSA P-256 pair when certFile/keyFile are missing or do not
// exist yet (default location under stateDir). It returns the SHA-256
// fingerprint of the leaf DER for pinning. Persisting keeps the fingerprint
// stable across restarts so clients don't need re-pinning.
func LoadOrCreateCert(certFile, keyFile, host string) (*tls.Certificate, string, error) {
	if certFile == "" || keyFile == "" {
		state := os.Getenv("LOCALAPPDATA")
		if state == "" {
			state = os.TempDir()
		}
		dir := filepath.Join(state, "opentunnel")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, "", err
		}
		certFile = filepath.Join(dir, "server-cert.pem")
		keyFile = filepath.Join(dir, "server-key.pem")
	}
	if _, err := os.Stat(certFile); err == nil {
		if _, err2 := os.Stat(keyFile); err2 == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, "", fmt.Errorf("transport: load keypair: %w", err)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return nil, "", fmt.Errorf("transport: parse leaf: %w", err)
			}
			return &cert, fmt.Sprintf("%x", FingerprintCert(leaf.Raw)), nil
		}
	}
	return generateAndSave(certFile, keyFile, host)
}

func generateAndSave(certFile, keyFile, host string) (*tls.Certificate, string, error) {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	leaf, _ := x509.ParseCertificate(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return nil, "", err
	}

	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert, fmt.Sprintf("%x", FingerprintCert(leaf.Raw)), nil
}
