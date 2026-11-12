package client

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMissingPublicKeyDoesNotRotatePrivateKey(t *testing.T) {
	s := &TokenStore{Dir: t.TempDir()}
	pub, err := s.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.SSHPrivatePath())
	if err := os.Remove(s.SSHPublicPath()); err != nil {
		t.Fatal(err)
	}
	got, err := s.EnsureSSHKey()
	after, _ := os.ReadFile(s.SSHPrivatePath())
	if err != nil || got != pub || !bytes.Equal(before, after) {
		t.Fatal("missing public-key cache rotated or corrupted the identity")
	}
	_ = os.WriteFile(s.SSHPublicPath(), []byte("corrupted cache"), 0o644)
	got, err = s.EnsureSSHKey()
	if err != nil || got != pub {
		t.Fatal("public-key cache was not repaired from the existing private key")
	}
}

func TestMissingPrivateKeyRequiresRecovery(t *testing.T) {
	s := &TokenStore{Dir: t.TempDir()}
	if _, err := s.EnsureSSHKey(); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(s.SSHPrivatePath())
	if _, err := s.EnsureSSHKey(); err == nil {
		t.Fatal("missing private key silently generated a replacement")
	}
}

func TestConcurrentIdentityCreationIsStable(t *testing.T) {
	s := &TokenStore{Dir: t.TempDir()}
	var wg sync.WaitGroup
	results := make(chan string, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			identity, err := s.LoadOrCreate()
			if err != nil {
				t.Error(err)
				return
			}
			results <- identity.Token
		}()
	}
	wg.Wait()
	close(results)
	var first string
	for got := range results {
		if first == "" {
			first = got
		}
		if got != first {
			t.Fatal("concurrent creation returned different device identities")
		}
	}
}

func TestCorruptIdentityIsNotSilentlyReplaced(t *testing.T) {
	s := &TokenStore{Dir: t.TempDir()}
	_ = os.WriteFile(s.TokenPath(), []byte("invalid-json"), 0o600)
	if _, err := s.LoadOrCreate(); err == nil {
		t.Fatal("invalid stored identity was silently replaced")
	}
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	s = &TokenStore{Dir: filepath.Join(blocked, "state")}
	if identity, err := s.LoadOrCreate(); err == nil || identity != nil {
		t.Fatal("unpersisted identity returned as success")
	}
}
