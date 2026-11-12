package privatefile

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateStateNoOverwriteAndBoundedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "fixture.json")
	if err := WriteNew(path, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("different")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrote state: %v", err)
	}
	if _, err := Read(path, 2); err == nil {
		t.Fatal("oversized state accepted")
	}
	if err := Write(path, []byte("updated")); err != nil {
		t.Fatal(err)
	}
	if data, err := Read(path, 1024); err != nil || string(data) != "updated" {
		t.Fatalf("state=%q err=%v", data, err)
	}
}

func TestPrivateReadRejectsInvalidLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := WriteNew(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{-1, math.MaxInt64} {
		if _, err := Read(path, limit); err == nil {
			t.Fatal("invalid bounded-read limit accepted")
		}
	}
}
