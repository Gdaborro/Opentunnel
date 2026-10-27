package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestSSHFailsClosedWithoutPins pins the audit round three F-2 residual
// fix: with no host-key pins and no explicit insecure override, the ssh
// tier must REFUSE to accept any host key (an unpinned ssh tier lets a
// middlebox relay the handshake and harvest the token).
func TestSSHFailsClosedWithoutPins(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	tr := &sshTransport{opt: SSHOptions{}}
	cb := tr.hostKeyCallback()
	if err := cb("host:22", nil, sshPub); err == nil {
		t.Fatal("empty pins must fail closed")
	}

	// Explicit dev override still allows.
	trInsecure := &sshTransport{opt: SSHOptions{InsecureHostKeys: true}}
	if err := trInsecure.hostKeyCallback()("host:22", nil, sshPub); err != nil {
		t.Fatalf("insecure override must accept: %v", err)
	}
}
