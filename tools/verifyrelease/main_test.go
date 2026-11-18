package main

import (
	"strings"
	"testing"
)

func TestCompatibilityVerifierCannotAuthorizePostCeilingRelease(t *testing.T) {
	err := verify(t.TempDir(), "v1.1.99")
	if err == nil || !strings.Contains(err.Error(), "full signed bundle") {
		t.Fatal("compatibility-only verifier was used to authorize a coordinated release", err)
	}
	if err := verify(t.TempDir(), "not-a-tag"); err == nil {
		t.Fatal("invalid release tag ignored")
	}
}
