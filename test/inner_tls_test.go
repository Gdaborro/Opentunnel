package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

func innerTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(123), Subject: pkix.Name{CommonName: "inner relay fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestInnerTLSOverH3RoundTripAndTeardown(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	db, err := panel.Open(filepath.Join(t.TempDir(), "inner-h3.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'inner-h3','approved',datetime('now'),datetime('now'),?,'fixture')`, device.Token, pub); err != nil {
		t.Fatal(err)
	}
	identity := innerTestCert(t)
	addr, fp := startH3ServerWithOptions(t, server.Options{PanelDB: db, AllowRestrictedTargets: true, InnerTLSCertificate: &identity, RequireInnerTLS: true})
	bulk := bytes.Repeat([]byte("inner-h3-fixture"), 1<<16)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bulk) }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	for range 10 {
		wrapped, err := client.WithInnerTLS(transport.NewH3(transport.H3Options{ServerAddr: addr, Fingerprint: fp}), []string{protocol.PublicKeyPin(identity.Leaf)})
		if err != nil {
			t.Fatal(err)
		}
		cl := client.NewWithOptions(wrapped, client.Options{Token: device.Token, Mux: true, DialTimeout: 5 * time.Second})
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		stream, err := cl.DialTunnel(ctx, mustParse(t, host, atoi(t, port)))
		if err != nil {
			cancel()
			_ = cl.Close()
			t.Fatal("inner TLS over H3 dial failed", err)
		}
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(stream, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
		data, err := io.ReadAll(stream)
		_ = stream.Close()
		_ = cl.Close()
		cancel()
		if err != nil || !bytes.HasSuffix(data, bulk) {
			t.Fatal("inner TLS over H3 bulk transfer failed", err)
		}
	}
}

func TestIndependentInnerMutualTLSPinningAndAdmission(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, err := client.NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	db, err := panel.Open(filepath.Join(t.TempDir(), "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'fixture','approved',datetime('now'),datetime('now'),?,'fixture')`, device.Token, pub); err != nil {
		t.Fatal(err)
	}
	identity := innerTestCert(t)
	relay := httptest.NewTLSServer(server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true, InnerTLSCertificate: &identity, RequireInnerTLS: true}))
	defer relay.Close()
	outer := func() transport.Transport {
		return transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: relay.Listener.Addr().String(), Fingerprint: hex.EncodeToString(transport.FingerprintCert(relay.Certificate().Raw))})
	}
	wrapped, err := client.WithInnerTLS(outer(), []string{protocol.PublicKeyPin(identity.Leaf)})
	if err != nil {
		t.Fatal(err)
	}
	cl := client.NewWithOptions(wrapped, client.Options{Token: device.Token, Mux: true, DialTimeout: 3 * time.Second})
	defer cl.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "independent session secret") }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	addr, _ := parseAddrForTest(host, port)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c, err := cl.DialTunnel(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
	data, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || !strings.Contains(string(data), "independent session secret") {
		t.Fatal("inner TLS target transfer failed", err)
	}
	bad, _ := client.WithInnerTLS(outer(), []string{strings.Repeat("a", 64)})
	if c, err := bad.Dial(ctx); err == nil {
		_ = c.Close()
		t.Fatal("inner relay pin mismatch accepted")
	}
	legacy := client.NewWithOptions(outer(), client.Options{Token: device.Token, Mux: true, DialTimeout: time.Second})
	defer legacy.Close()
	if c, err := legacy.DialTunnel(ctx, addr); err == nil {
		_ = c.Close()
		t.Fatal("required inner TLS silently downgraded")
	}
	if err := db.PeerStateAction(device.Token, "expire", "", ""); err != nil {
		t.Fatal(err)
	}
	if c, err := wrapped.Dial(ctx); err == nil {
		_ = c.Close()
		t.Fatal("expired device completed inner mutual TLS")
	}
}
