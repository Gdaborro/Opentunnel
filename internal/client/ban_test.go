//go:build windows

package client

import (
	"os"
	"testing"
)

type memoryBanBackend struct {
	reason, duration string
	present          bool
}

func (b *memoryBanBackend) Banned() bool { return b.present }
func (b *memoryBanBackend) Write(reason, duration string) {
	b.reason, b.duration, b.present = reason, duration, true
}
func (b *memoryBanBackend) Clear() { b.reason, b.duration, b.present = "", "", false }

// Never snapshot/mutate/restore the real user's registry as a test fixture.
func TestBanRoundTrip(t *testing.T) {
	original := banState
	memory := &memoryBanBackend{}
	banState = memory
	t.Cleanup(func() { banState = original })
	store := &TokenStore{Dir: t.TempDir()}
	if store.IsHardBanned() {
		t.Fatal("fresh fixture is banned")
	}
	store.WriteHardBan("test reason", "permanent")
	if !store.IsHardBanned() || memory.reason != "test reason" {
		t.Fatal("ban not persisted in isolated backend")
	}
	if data, err := os.ReadFile(store.BanPath()); err != nil || len(data) == 0 {
		t.Fatal("file ban missing")
	}
	store.ClearBan()
	if store.IsHardBanned() {
		t.Fatal("ban not cleared")
	}
}
