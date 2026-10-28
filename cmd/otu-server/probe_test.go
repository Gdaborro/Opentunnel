package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCA mints a CA and a leaf for serverName, returning the TLS cert,
// the CA pool, and the expected leaf fingerprint.
func testCA(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "probe-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leafDER)
	fp := hex.EncodeToString(sum[:])

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, pool, fp
}

func serveTLS(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
			go func() { _ = tc.Handshake(); _ = tc.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// TestPinProbeRefusesUnverifiedLeaves pins the audit round four fix: only
// a chain-verified leaf may become an announced pin. A self-signed
// endpoint (the poison scenario) must be rejected; a CA-signed endpoint
// must be accepted and fingerprinted exactly.
func TestPinProbeRefusesUnverifiedLeaves(t *testing.T) {
	const sni = "probe.test"

	// Poison: a leaf signed by a private CA the system roots know nothing
	// about (exactly what an on-path redirection would serve).
	poisonCert, _, _ := testCA(t, sni)
	poisonAddr := serveTLS(t, poisonCert)
	if fp, err := probeVerifiedLeaf(poisonAddr, sni, nil); err == nil {
		t.Fatalf("self-signed/private-CA leaf must be rejected, got fp %s", fp)
	}

	// Legit: same shape, but the probe trusts the CA (system roots in
	// production; injected here).
	goodCert, pool, wantFP := testCA(t, sni)
	goodAddr := serveTLS(t, goodCert)
	fp, err := probeVerifiedLeaf(goodAddr, sni, pool)
	if err != nil {
		t.Fatalf("CA-signed leaf rejected: %v", err)
	}
	if fp != wantFP {
		t.Fatalf("fingerprint = %s, want %s", fp, wantFP)
	}

	// Hostname mismatch must also fail even with a trusted chain.
	if _, err := probeVerifiedLeaf(goodAddr, "other.test", pool); err == nil {
		t.Fatal("hostname-mismatched leaf must be rejected")
	}
}
