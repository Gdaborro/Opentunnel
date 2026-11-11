package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// TestCanonicalSSHPubKey (1.0.1, N-11 chain): registration-time junk and
// newline-smuggled keys must be refused; valid lines canonicalize without
// their comment.
func TestCanonicalSSHPubKey(t *testing.T) {
	good := testKeyLine(t)

	if got, ok := CanonicalSSHPubKey(good); !ok || got != good {
		t.Fatalf("valid key rejected/altered: %q ok=%v", got, ok)
	}
	if got, ok := CanonicalSSHPubKey(good + " user@host"); !ok || got != good {
		t.Fatalf("comment not dropped: %q ok=%v", got, ok)
	}
	if _, ok := CanonicalSSHPubKey(good + "\n" + good + " evil"); ok {
		t.Fatal("newline-smuggled key accepted")
	}
	if _, ok := CanonicalSSHPubKey(good + "\r\n" + good); ok {
		t.Fatal("CRLF-smuggled key accepted")
	}
	if _, ok := CanonicalSSHPubKey("ssh-rsa AAAAB3NzaC1yc2EAAAA"); ok {
		t.Fatal("non-ed25519 accepted")
	}
	for _, bad := range []string{"", "garbage", "ssh-ed25519"} {
		if _, ok := CanonicalSSHPubKey(bad); ok {
			t.Fatalf("bad input %q accepted", bad)
		}
	}
}

func TestConcurrentAuthorizedKeyUpdatesDoNotLoseKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	keys := make([]string, 16)
	for i := range keys {
		keys[i] = testKeyLine(t)
	}
	var wg sync.WaitGroup
	for _, key := range keys {
		wg.Add(1)
		go func(pub string) {
			defer wg.Done()
			if _, err := UpsertAuthorizedKey(path, pub, "127.0.0.1:8081"); err != nil {
				t.Error(err)
			}
		}(key)
	}
	wg.Wait()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if strings.Count(string(raw), key) != 1 {
			t.Fatal("concurrent update lost or duplicated a key")
		}
	}
}

func TestUpsertRemovesDuplicateTargetKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	key := testKeyLine(t)
	line := CanonicalAuthorizedKeyLine(key, "127.0.0.1:8081") + "\n"
	if err := os.WriteFile(path, []byte(line+line), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertAuthorizedKey(path, key, "127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), key) != 1 {
		t.Fatal("duplicate authorization survived upsert")
	}
}

// TestReconcileAuthorizedKeys: the startup self-heal adds missing
// approved keys, preserves every existing line (including a legacy shared
// key), is idempotent, ignores junk, and refuses to create a missing file
// (the caller gates on the sshd-managed file existing).
func TestReconcileAuthorizedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	a := testKeyLine(t)
	b := testKeyLine(t)
	legacy := testKeyLine(t)

	if _, err := UpsertAuthorizedKey(path, a, "127.0.0.1:8081"); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(CanonicalAuthorizedKeyLine(legacy, "127.0.0.1:8081") + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	n, err := ReconcileAuthorizedKeys(path, "127.0.0.1:8081", []string{a, b, "junk", ""})
	if err != nil || n != 1 {
		t.Fatalf("reconcile: n=%d err=%v (want 1 added)", n, err)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	for _, k := range []string{a, b, legacy} {
		if !strings.Contains(text, k) {
			t.Fatalf("key missing after reconcile: %q\n%s", k, text)
		}
	}
	if strings.Contains(text, "junk") {
		t.Fatalf("junk must never reach the file: %s", text)
	}

	if n, err = ReconcileAuthorizedKeys(path, "127.0.0.1:8081", []string{a, b}); err != nil || n != 0 {
		t.Fatalf("second reconcile must be a no-op: n=%d err=%v", n, err)
	}
	if _, err = ReconcileAuthorizedKeys(filepath.Join(t.TempDir(), "missing"), "127.0.0.1:8081", []string{a}); err == nil {
		t.Fatal("missing file must error, not be created")
	}
}

// TestAuthorizedKeyLifecycle (1.0.1, N-11/N-12): canonical lines carry the
// forced command, upserts are idempotent and clean junk, and revocation
// removes exactly the revoked key.
func TestAuthorizedKeyLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	a := testKeyLine(t)
	b := testKeyLine(t)

	changed, err := UpsertAuthorizedKey(path, a, "127.0.0.1:8081")
	if err != nil || !changed {
		t.Fatalf("first upsert: changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `command="`+SSHForcedCommand+`"`) {
		t.Fatalf("canonical line missing forced command (N-11): %s", raw)
	}
	if strings.Count(strings.TrimRight(string(raw), "\n"), "\n") != 0 {
		t.Fatalf("want exactly 1 line, got: %q", raw)
	}

	if changed, err = UpsertAuthorizedKey(path, a, "127.0.0.1:8081"); err != nil || changed {
		t.Fatalf("second upsert must be a no-op: changed=%v err=%v", changed, err)
	}

	if changed, err = UpsertAuthorizedKey(path, b, "127.0.0.1:8081"); err != nil || !changed {
		t.Fatalf("second key upsert: changed=%v err=%v", changed, err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Count(strings.TrimRight(string(raw), "\n"), "\n") != 1 {
		t.Fatalf("want 2 lines, got: %q", raw)
	}

	// A junk line introduced behind our back is dropped on the next write.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-a-key junk\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if changed, err = UpsertAuthorizedKey(path, b, "127.0.0.1:8082"); err != nil || !changed {
		t.Fatalf("upsert with junk: changed=%v err=%v", changed, err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), "junk") {
		t.Fatalf("junk line survived: %q", raw)
	}

	// N-12: revocation removes only the target key.
	if changed, err = RemoveAuthorizedKey(path, a); err != nil || !changed {
		t.Fatalf("revoke: changed=%v err=%v", changed, err)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), a) || !strings.Contains(string(raw), b) {
		t.Fatalf("wrong key removed: %q", raw)
	}
	if changed, err = RemoveAuthorizedKey(path, a); err != nil || changed {
		t.Fatalf("second revoke must be a no-op: changed=%v err=%v", changed, err)
	}
}
