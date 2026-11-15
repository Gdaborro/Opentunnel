package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
)

func TestPoolRelayRequiresEnrollmentApprovalAndV5Immediately(t *testing.T) {
	db, err := panel.Open(filepath.Join(t.TempDir(), "pool.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	poolID := strings.Repeat("a", 64)
	info, err := db.BindServerPool(poolID, true)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	const token = "synthetic-relay-pool-device-token"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,ssh_pubkey,status,created_at,last_seen,auth_epoch) VALUES(?,'synthetic-fp',?,'approved',datetime('now'),datetime('now'),'epoch')`, token, canonical); err != nil {
		t.Fatal(err)
	}
	opt := Options{PanelDB: db, PoolID: poolID, AuthorityID: info.AuthorityID, RequireV5After: time.Now().Add(24 * time.Hour)}
	dial := func(o Options, v5 bool, signer ed25519.PrivateKey) byte {
		a, b := net.Pipe()
		defer a.Close()
		_ = a.SetDeadline(time.Now().Add(2 * time.Second))
		done := make(chan struct{})
		go func() { defer close(done); handleSession(b, o, "192.0.2.100", "") }()
		if v5 {
			salt := protocol.RandomSalt()
			if err := protocol.WriteHandshakeV5(a, token, salt, ed25519.Sign(signer, protocol.HandshakeMsg(token, salt))); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := protocol.WriteHandshake(a, token); err != nil {
				t.Fatal(err)
			}
		}
		_, status, err := protocol.ReadHandshakeStatus(a)
		if err != nil {
			t.Fatal(err)
		}
		_ = a.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("relay setup did not terminate")
		}
		return status
	}
	if st := dial(opt, true, key); st != protocol.StatusPending {
		t.Fatal("raw approved row bypassed enrollment", st)
	}
	if _, err := db.Exec(`INSERT INTO enrollment_accounts(username,password_hash) VALUES('synthetic-user','not-used-in-handshake')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peer_enrollments(token,username,pool_id,public_key) VALUES(?,'synthetic-user',?,?)`, token, poolID, canonical); err != nil {
		t.Fatal(err)
	}
	if st := dial(opt, false, key); st != protocol.StatusBadToken {
		t.Fatal("never-v5 peer downgraded inside trusted pool", st)
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if st := dial(opt, true, wrong); st != protocol.StatusBadToken {
		t.Fatal("wrong device key accepted", st)
	}
	if st := dial(opt, true, key); st != protocol.StatusOK {
		t.Fatal("signed approved device refused", st)
	}
	if _, err := db.Exec(`UPDATE peers SET approval_required=1 WHERE token=?`, token); err != nil {
		t.Fatal(err)
	}
	if st := dial(opt, true, key); st != protocol.StatusPending {
		t.Fatal("manual approval latch bypassed", st)
	}
	if _, err := db.Exec(`UPDATE peers SET approval_required=0 WHERE token=?`, token); err != nil {
		t.Fatal(err)
	}
	wrongAuthority := opt
	wrongAuthority.AuthorityID = strings.Repeat("f", 64)
	if st := dial(wrongAuthority, true, key); st == protocol.StatusOK {
		t.Fatal("relay used independent approval authority")
	}
	noScope := opt
	noScope.PoolID, noScope.AuthorityID = "", ""
	if st := dial(noScope, true, key); st == protocol.StatusOK {
		t.Fatal("pool DB downgraded via unscoped embedder")
	}
	if err := db.PeerStateAction(token, "ban", "synthetic revocation", "permanent"); err != nil {
		t.Fatal(err)
	}
	if st := dial(opt, true, key); st != protocol.StatusBanned {
		t.Fatal("banned pool device admitted", st)
	}
}

func TestPoolRejectsLegacyStaticAndCompatibilityAuthority(t *testing.T) {
	pool := strings.Repeat("a", 64)
	for _, opt := range []Options{{PoolID: pool, Token: "legacy-master"}, {PoolID: pool, AuthorityID: pool, PanelDB: v5Stub{token: "fixture", pubkey: "fixture"}, AllowLegacyMaster: true, Token: "fixture"}} {
		if _, err := opt.readPolicy("fixture"); err == nil {
			t.Fatal("pool fell back to legacy/non-authoritative policy")
		}
		if opt.verifyHandshakeToken("fixture") == protocol.StatusOK {
			t.Fatal("legacy pool token accepted")
		}
	}
}
