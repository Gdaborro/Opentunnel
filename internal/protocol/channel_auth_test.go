package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"testing"
)

func TestChannelProofBindsExactConnectionTokenAndSalt(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	binding := bytes.Repeat([]byte{1}, 32)
	salt := RandomSalt()
	token := "synthetic-channel-token-123456"
	msg, err := ChannelHandshakeMsg(token, salt, binding)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, msg)
	for _, changed := range []struct {
		token         string
		salt, binding []byte
	}{{token, salt, bytes.Repeat([]byte{2}, 32)}, {token + "x", salt, binding}, {token, bytes.Repeat([]byte{3}, SaltSize), binding}} {
		other, err := ChannelHandshakeMsg(changed.token, changed.salt, changed.binding)
		if err != nil {
			t.Fatal(err)
		}
		if ed25519.Verify(pub, other, sig) {
			t.Fatal("captured proof authenticated another TLS connection/token/salt")
		}
	}
	var frame bytes.Buffer
	if err := WriteChannelHandshake(&frame, token, salt, sig); err != nil {
		t.Fatal(err)
	}
	hs, err := ReadHandshake(&frame)
	if err != nil || hs.Version != ChannelVersion || hs.Token != token || !bytes.Equal(hs.Sig, sig) {
		t.Fatal("channel frame round trip", err)
	}
	if _, err := ChannelBinding(tls.ConnectionState{Version: tls.VersionTLS12}); err == nil {
		t.Fatal("unbound transport accepted")
	}
}
