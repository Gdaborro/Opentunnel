package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
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
	v5      *atomic.Bool // set when MarkV5 fires (sticky latch state)
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
func (v v5Stub) MarkV5(tok string) {
	if v.v5 != nil && tok == v.token {
		v.v5.Store(true)
	}
}
func (v v5Stub) V5Seen(tok string) bool {
	return v.v5 != nil && tok == v.token && v.v5.Load()
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

// TestV4DowngradeGate pins the audit round four fix: once a peer has
// authenticated with a signature-verified v5 session, v4 handshakes for
// its token are refused (a harvested token must not survive by
// downgrading). Never-upgraded peers stay admitted until the optional
// enforcement date passes.
func TestV4DowngradeGate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	authKey := string(ssh.MarshalAuthorizedKey(sshPub))

	const tok = "gate-token-1234567890abcdef"
	var v5State atomic.Bool
	var alerts []string

	dialV4 := func(opt Options) byte {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go handleSession(c2, opt, "203.0.113.9")
		if err := protocol.WriteHandshake(c1, tok); err != nil {
			t.Fatalf("write v4: %v", err)
		}
		_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, st, rerr := protocol.ReadHandshakeStatus(c1)
		if rerr != nil {
			t.Fatalf("read status: %v", rerr)
		}
		return st
	}
	dialV5 := func(opt Options) byte {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go handleSession(c2, opt, "203.0.113.9")
		salt := protocol.RandomSalt()
		sig := ed25519.Sign(priv, protocol.HandshakeMsg(tok, salt))
		if err := protocol.WriteHandshakeV5(c1, tok, salt, sig); err != nil {
			t.Fatalf("write v5: %v", err)
		}
		_ = c1.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, st, rerr := protocol.ReadHandshakeStatus(c1)
		if rerr != nil {
			t.Fatalf("read status: %v", rerr)
		}
		return st
	}

	opt := Options{Token: "master", PanelDB: v5Stub{token: tok, pubkey: authKey, alerts: &alerts, v5: &v5State}}

	// 1. Never-upgraded peer: v4 admitted (migration window).
	if st := dialV4(opt); st != protocol.StatusOK {
		t.Fatalf("fresh peer v4: status=%d, want OK", st)
	}

	// 2. One v5 session latches the peer.
	if st := dialV5(opt); st != protocol.StatusOK {
		t.Fatalf("v5: status=%d, want OK", st)
	}
	if !v5State.Load() {
		t.Fatal("MarkV5 must latch after a verified v5 session")
	}

	// 3. The downgrade attempt: v4 for the latched peer is refused.
	before := len(alerts)
	if st := dialV4(opt); st != protocol.StatusBadToken {
		t.Fatalf("downgrade v4: status=%d, want BadToken", st)
	}
	if len(alerts) == before {
		t.Fatal("downgrade attempt must raise a security alert")
	}

	// 4. Enforcement date in the future: unlatched peer still admitted.
	futureOpt := opt
	futureOpt.PanelDB = v5Stub{token: tok, pubkey: authKey, alerts: &alerts, v5: &atomic.Bool{}}
	futureOpt.RequireV5After = time.Now().Add(24 * time.Hour)
	if st := dialV4(futureOpt); st != protocol.StatusOK {
		t.Fatalf("pre-date v4: status=%d, want OK", st)
	}

	// 5. Enforcement date passed: v4 refused even without v5_seen.
	pastOpt := futureOpt
	pastOpt.RequireV5After = time.Now().Add(-time.Hour)
	if st := dialV4(pastOpt); st != protocol.StatusBadToken {
		t.Fatalf("post-date v4: status=%d, want BadToken", st)
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
