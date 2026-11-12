package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"
)

var InnerTLSMarker = [4]byte{'O', 'T', 'I', '1'}
var InnerTLSConfirmed = [4]byte{'O', 'T', 'I', 'A'}

const InnerTLSALPN = "otu-inner/1"

// DeviceCertificate uses the enrolled device signing key in a short-lived
// self-signed TLS credential. Authentication relies on pin/key possession,
// not a public CA or an interceptor's system root. TLS 1.3 supplies challenges
// and independent ephemeral session keys; 0-RTT/session tickets are disabled.
func DeviceCertificate(token string, key ed25519.PrivateKey) (tls.Certificate, error) {
	if len(token) < 16 || len(token) > 128 || len(key) != ed25519.PrivateKeySize {
		return tls.Certificate{}, errors.New("invalid inner TLS identity")
	}
	for _, r := range token {
		if r != '_' && r != '-' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return tls.Certificate{}, errors.New("invalid inner TLS identity")
		}
	}
	u, err := url.Parse("urn:opentunnel:device:" + token)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "opentunnel device"}, URIs: []*url.URL{u}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func InnerTLSToken(cert *x509.Certificate) (string, error) {
	if cert == nil || len(cert.URIs) != 1 || cert.URIs[0].Scheme != "urn" || !strings.HasPrefix(cert.URIs[0].Opaque, "opentunnel:device:") {
		return "", errors.New("invalid inner TLS certificate identity")
	}
	token := strings.TrimPrefix(cert.URIs[0].Opaque, "opentunnel:device:")
	if len(token) < 16 || len(token) > 128 {
		return "", errors.New("invalid inner TLS token")
	}
	return token, nil
}

// PublicKeyPin pins the DER SubjectPublicKeyInfo rather than a renewing leaf.
func PublicKeyPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func ParsePublicKeyPin(value string) ([32]byte, error) {
	var pin [32]byte
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 32 {
		return pin, errors.New("inner TLS requires a SHA-256 public-key pin")
	}
	copy(pin[:], b)
	return pin, nil
}
