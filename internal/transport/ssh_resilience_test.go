package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHSetupDeadlineCoversSilentPeer(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(key, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture-key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-stop // accept TCP but never send an SSH identification/KEX packet
	}()
	tr := NewSSH(SSHOptions{Host: ln.Addr().String(), User: "fixture", KeyFile: path,
		InternalWS: "127.0.0.1:8081", InsecureHostKeys: true, DialTimeout: 70 * time.Millisecond})
	done := make(chan error, 1)
	go func() {
		conn, err := tr.Dial(context.Background())
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent SSH peer unexpectedly connected")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SSH timeout only bounded TCP, not the handshake")
	}
}

func TestCurrentPinIsVerifiedForResumedTLSState(t *testing.T) {
	cert, fp, err := LoadOrCreateCert(filepath.Join(t.TempDir(), "c"), filepath.Join(t.TempDir(), "k"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{DidResume: true, PeerCertificates: []*x509.Certificate{leaf}}
	good, err := (&wsTLSTransport{opt: WSTLSOptions{Fingerprint: fp}}).tlsConfig("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if good.VerifyConnection == nil || good.VerifyConnection(state) != nil {
		t.Fatal("resumed connection did not verify the accepted pin")
	}
	bad, err := (&wsTLSTransport{opt: WSTLSOptions{Fingerprint: strings.Repeat("ab", 32)}}).tlsConfig("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if bad.VerifyConnection(state) == nil {
		t.Fatal("cached session bypassed the current pin set")
	}
}
