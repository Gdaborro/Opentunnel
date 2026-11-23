package test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

func TestIndependentChannelAuthenticationRoundTripAndNoCapturedProofReuse(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, _ := client.NewTokenStore()
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	db, err := panel.Open(filepath.Join(t.TempDir(), "channel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'channel','approved',datetime('now'),datetime('now'),?,'channel-generation')`, device.Token, pub); err != nil {
		t.Fatal(err)
	}
	identity := innerTestCert(t)
	relay := httptest.NewTLSServer(server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true, InnerTLSCertificate: &identity, RequireInnerTLS: true, RequireChannelAuth: true}))
	defer relay.Close()
	outer := func() transport.Transport {
		return transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: relay.Listener.Addr().String(), Fingerprint: hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw))})
	}
	inner, err := client.WithInnerTLS(outer(), []string{protocol.PublicKeyPin(identity.Leaf)})
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithOptions(inner, client.Options{RequireChannelAuth: true, Mux: true, DialTimeout: 3 * time.Second})
	defer cl.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "channel-bound payload") }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	target, err := parseAddrForTest(host, port)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cl.DialTunnel(t.Context(), target)
	if err != nil {
		t.Fatal("channel authentication failed", err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: synthetic\r\n\r\n")
	raw, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || !bytes.Contains(raw, []byte("channel-bound payload")) {
		t.Fatal("channel traffic failed", err)
	}
	// Capture a real accepted possession proof on an actual TLS exporter.
	keyRaw, err := os.ReadFile(store.SSHPrivatePath())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ssh.ParseRawPrivateKey(keyRaw)
	if err != nil {
		t.Fatal(err)
	}
	var key ed25519.PrivateKey
	switch parsed := parsed.(type) {
	case ed25519.PrivateKey:
		key = parsed
	case *ed25519.PrivateKey:
		key = *parsed
	default:
		t.Fatal("fixture signing key type")
	}
	salt := protocol.RandomSalt()
	captured, err := inner.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = captured.SetDeadline(time.Now().Add(2 * time.Second))
	bound, err := protocol.ChannelBinding(captured.(*tls.Conn).ConnectionState())
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := protocol.ChannelHandshakeMsg(device.Token, salt, bound)
	proof := ed25519.Sign(key, msg)
	if err := protocol.WriteChannelHandshake(captured, device.Token, salt, proof); err != nil {
		t.Fatal(err)
	}
	_, status, err := protocol.ReadHandshakeStatus(captured)
	if err != nil || status != protocol.StatusOK {
		t.Fatal("captured fixture proof was never accepted", err)
	}
	_ = captured.Close()
	// Restart the handler with a fresh (empty) replay cache: neither cache TTL
	// nor process persistence is the connection-authentication defense.
	restarted := httptest.NewTLSServer(server.Handler(server.Options{PanelDB: db, InnerTLSCertificate: &identity, RequireInnerTLS: true, RequireChannelAuth: true, ReplayCache: protocol.NewReplayCache(time.Millisecond, 16)}))
	defer restarted.Close()
	restartedOuter := transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: restarted.Listener.Addr().String(), Fingerprint: hex.EncodeToString(transport.FingerprintCert(restarted.Certificate().Raw))})
	restartedInner, err := client.WithInnerTLS(restartedOuter, []string{protocol.PublicKeyPin(identity.Leaf)})
	if err != nil {
		t.Fatal(err)
	}
	for _, carrier := range []transport.Transport{inner, restartedInner} {
		conn, err := carrier.Dial(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		other, err := protocol.ChannelBinding(conn.(*tls.Conn).ConnectionState())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(bound, other) {
			t.Fatal("distinct independent TLS sessions shared exporter material")
		}
		if err := protocol.WriteChannelHandshake(conn, device.Token, salt, proof); err != nil {
			t.Fatal(err)
		}
		_, status, err := protocol.ReadHandshakeStatus(conn)
		_ = conn.Close()
		if err == nil && status == protocol.StatusOK {
			t.Fatal("captured accepted proof authorized new connection/restarted relay")
		}
	}
	legacy := client.NewWithOptions(inner, client.Options{Mux: true, DialTimeout: time.Second})
	defer legacy.Close()
	if c, err := legacy.DialTunnel(t.Context(), target); err == nil {
		c.Close()
		t.Fatal("explicit channel requirement accepted v5 downgrade")
	}
}
