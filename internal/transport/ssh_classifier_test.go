package transport

import (
	"errors"
	"strings"
	"testing"
)

// TestSSHAuthRejectionClassifier: only x/crypto's authentication-failure
// text classifies as a key rejection; transport errors must stay generic.
func TestSSHAuthRejectionClassifier(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain", true},
		{"ssh: handshake failed: ssh: no supported methods remain", true},
		{"ssh: handshake failed: dial tcp 1.2.3.4:22: connect: connection refused", false},
		{"ssh: handshake failed: ssh: handshake failed: EOF", false},
		{"", false},
	}
	for _, c := range cases {
		var err error
		if c.msg != "" {
			err = errors.New(c.msg)
		}
		if got := isSSHAuthRejection(err); got != c.want {
			t.Errorf("isSSHAuthRejection(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

// TestSSHKeyRejectedErrorShape: the typed error carries a human sentence
// and unwraps to the raw cause (the adaptive dialer keys its ssh-tier
// backoff on the type, logs the sentence).
func TestSSHKeyRejectedErrorShape(t *testing.T) {
	raw := errors.New("ssh: unable to authenticate, attempted methods [none publickey]")
	rej := &SSHKeyRejectedError{Host: "host:22", Err: raw}
	if !strings.Contains(rej.Error(), "re-approval") {
		t.Fatalf("error text must tell the operator what to do: %q", rej.Error())
	}
	if !errors.Is(rej, raw) {
		t.Fatal("typed error must unwrap to the raw cause")
	}
}
