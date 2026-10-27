package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"opentunnel/internal/protocol"
)

// v5Stub is the minimal PanelDB for v5 handshake tests: one known token
// with a known key, everything else inert.
type v5Stub struct {
	token   string
	pubkey  string
	alerts  *[]string
	onAllow func()
}

func (v v5Stub) CheckToken(tok string) (string, string, string, error) {
	if tok == v.token {
		return "approved", "", "", nil
	}
	return "pending", "", "", nil
}
func (v v5Stub) RecordTraffic(string, int64, int64) {}
func (v v5Stub) IsBlocked(string) bool              { return false }
func (v v5Stub) BlockWhy(string) string             { return "" }
func (v v5Stub) KillSwitch() bool                   { return false }
func (v v5Stub) PeerLimits(string) (int64, int64)   { return 0, 0 }
func (v v5Stub) SetPeerIP(string, string)           {}
func (v v5Stub) RecordHealth(string, string, string, string, float64, float64, float64, int64, float64, float64, float64) {
}
func (v v5Stub) BanReason(string) string    { return "" }
func (v v5Stub) TouchPeer(string)           {}
func (v v5Stub) KnownPeer(tok string) bool  { return tok == v.token }
func (v v5Stub) RecordVisit(string, string) {}
func (v v5Stub) SSHPubKey(tok string) string {
	if tok == v.token {
		return v.pubkey
	}
	return ""
}
func (v v5Stub) RecordAlert(sev, kind, msg string) {
	if v.alerts != nil {
		*v.alerts = append(*v.alerts, sev+"|"+kind+"|"+msg)
	}
}

// TestV5HandshakeSignatureEnforcement: with a registered key on file, the
// relay must accept only correctly-signed v5 handshakes and answer
// BadToken (plus a security alert) for a valid token without the key
// (audit round three, N-1/N-2: the stolen-token path).
func TestV5HandshakeSignatureEnforcement(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	authKey := string(ssh.MarshalAuthorizedKey(sshPub))

	const tok = "v5-token-1234567890abcdef"
	var alerts []string
	opt := Options{Token: "master", PanelDB: v5Stub{token: tok, pubkey: authKey, alerts: &alerts}}

	run := func(sig []byte) (byte, error) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go handleSession(c2, opt, "203.0.113.9")
		salt := protocol.RandomSalt()
		if sig == nil {
			sig = ed25519.Sign(priv, protocol.HandshakeMsg(tok, salt))
		}
		if err := protocol.WriteHandshakeV5(c1, tok, salt, sig); err != nil {
			t.Fatalf("write v5: %v", err)
		}
		_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, st, err := protocol.ReadHandshakeStatus(c1)
		if err != nil {
			return 0, err
		}
		return st, nil
	}

	// Correct signature → OK.
	st, err := run(nil)
	if err != nil || st != protocol.StatusOK {
		t.Fatalf("good signature: status=%d err=%v, want OK", st, err)
	}

	// Valid token, wrong key (stolen-token scenario) → BadToken + alert.
	wrongPub, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = wrongPub
	salt := protocol.RandomSalt()
	badSig := ed25519.Sign(wrongPriv, protocol.HandshakeMsg(tok, salt))
	st, err = run(badSig)
	if err != nil || st != protocol.StatusBadToken {
		t.Fatalf("wrong-key signature: status=%d err=%v, want BadToken", st, err)
	}
	if len(alerts) == 0 {
		t.Fatal("signature mismatch must raise a security alert")
	}
	if got := alerts[0]; len(got) < 18 || got[:18] != "critical|security|" {
		t.Fatalf("unexpected alert: %q", got)
	}

	// Legacy v4 handshake still accepted during the migration window.
	c1, c2 := net.Pipe()
	defer c1.Close()
	go handleSession(c2, opt, "203.0.113.9")
	if err := protocol.WriteHandshake(c1, tok); err != nil {
		t.Fatal(err)
	}
	_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
	ver, st, err := protocol.ReadHandshakeStatus(c1)
	if err != nil || st != protocol.StatusOK || ver != protocol.ProtoVersionLegacy {
		t.Fatalf("legacy handshake: ver=%d status=%d err=%v", ver, st, err)
	}
}

// TestH3ServerConnDeadlineInterruptsReads: the server shim must unblock a
// stalled read with os.ErrDeadlineExceeded so the guard slot frees in the
// handshake window (audit round three, N-4).
func TestH3ServerConnDeadlineInterruptsReads(t *testing.T) {
	br := newBlockingReaderServer()
	c := &h3ServerConn{Reader: br, Writer: io.Discard}
	if err := c.SetDeadline(time.Now().Add(120 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := c.Read(make([]byte, 8))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read err = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline too slow: %v", elapsed)
	}
	// Writes after expiry also fail fast.
	if _, err := c.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write err = %v, want deadline exceeded", err)
	}
	_ = br.Close()
}

type blockingReaderServer struct{ ch chan struct{} }

func newBlockingReaderServer() *blockingReaderServer {
	return &blockingReaderServer{ch: make(chan struct{})}
}
func (b *blockingReaderServer) Read(p []byte) (int, error) {
	<-b.ch
	return 0, io.EOF
}
func (b *blockingReaderServer) Close() error { close(b.ch); return nil }
