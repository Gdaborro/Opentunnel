package serverpool

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignedChannelPolicyRequiresPinsAndCannotDowngrade(t *testing.T) {
	p, key, now := testProfile(t)
	store := Store{Dir: t.TempDir()}
	if err := store.Import(p, true, now); err != nil {
		t.Fatal(err)
	}
	p.IssuedAt++
	p.RequireChannelAuth = true
	if err := p.Sign(key, now); err == nil {
		t.Fatal("channel profile accepted a node without independent TLS")
	}
	p.Nodes[0].InnerTLSPins = []string{strings.Repeat("c", 64)}
	if err := p.Sign(key, now); err != nil {
		t.Fatal(err)
	}
	if p.Version != ChannelProfileVersion {
		t.Fatal("old clients could ignore a new authentication policy")
	}
	if err := store.Import(p, true, now); err != nil {
		t.Fatal(err)
	}
	tampered := p
	tampered.RequireChannelAuth = false
	if err := tampered.Verify(now); err == nil {
		t.Fatal("unsigned requirement change accepted")
	}
	tampered.IssuedAt++
	if err := tampered.Sign(key, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Import(tampered, true, now); err == nil {
		t.Fatal("newer signed profile reopened downgrade")
	}
}

func TestLegacyProfileCanonicalSignatureRemainsCompatible(t *testing.T) {
	p, _, now := testProfile(t)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "require_channel_auth") {
		t.Fatal("legacy signed canonical bytes changed")
	}
	decoded, err := Decode(raw)
	if err != nil || decoded.Verify(now) != nil || decoded.Version != 1 {
		t.Fatal("legacy profile lost compatibility", err)
	}
	if err := decoded.Verify(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}
