package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHHostKeyPinMatching(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(hostKey.Marshal())
	// ssh-keygen -lf style: SHA256:<base64 without padding>
	pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	tr := &sshTransport{opt: SSHOptions{HostKeyPins: []string{pin}}}
	cb := tr.hostKeyCallback()
	if err := cb("host:22", nil, hostKey); err != nil {
		t.Fatalf("correct pin rejected: %v", err)
	}

	// Padded variant (as produced by naive base64 encoders) must also match.
	trPadded := &sshTransport{opt: SSHOptions{HostKeyPins: []string{pin + "="}}}
	if err := trPadded.hostKeyCallback()("host:22", nil, hostKey); err != nil {
		t.Fatalf("padded pin rejected: %v", err)
	}

	trWrong := &sshTransport{opt: SSHOptions{HostKeyPins: []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}
	if err := trWrong.hostKeyCallback()("host:22", nil, hostKey); err == nil {
		t.Fatal("wrong pin accepted")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}
