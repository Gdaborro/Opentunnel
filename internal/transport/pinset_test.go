package transport

import (
	"encoding/hex"
	"testing"
)

// TestVerifyPinSetAcceptsRotation: any pin in the set verifies the leaf —
// a renewal pin joins the set without touching the configured primary.
// A set without the leaf's pin rejects, and a pinless config fails closed
// at build time.
func TestVerifyPinSetAcceptsRotation(t *testing.T) {
	tmp := t.TempDir()
	cert, fp, err := LoadOrCreateCert(tmp+"/c.pem", tmp+"/k.pem", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Certificate[0]
	got := FingerprintCert(leaf)

	bogus := make([]byte, 32)
	bogus[0] = 0xFF
	if hex.EncodeToString(bogus) == fp {
		t.Fatal("test bug: bogus pin collides with the real one")
	}

	if err := VerifyPinSet([][]byte{bogus, got}, [][]byte{leaf}); err != nil {
		t.Fatalf("rotation set must accept the leaf: %v", err)
	}
	if err := VerifyPinSet([][]byte{bogus}, [][]byte{leaf}); err == nil {
		t.Fatal("unknown leaf must be rejected")
	}

	pins, err := buildPinSet(fp, []string{hex.EncodeToString(bogus)})
	if err != nil || len(pins) != 2 {
		t.Fatalf("buildPinSet = %v, %v; want both pins", pins, err)
	}
	if _, err := buildPinSet("", nil); err == nil {
		t.Fatal("pinless non-insecure config must fail closed")
	}
}
