package client

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/transport"
)

func TestRuntimeStatusNeverIncludesDeviceOrCarrierSecrets(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	cfg := &config.ClientConf{ServerAddr: "entry.example:443", Token: "NEVER-DISCLOSE-SHARED-TOKEN", SSHKey: "private-key-path", CarrierSOCKS: "127.0.0.1:19090", RequireChannelAuth: true}
	a := NewAdaptive("secret", transport.WSTLSOptions{}, "fast", time.Second)
	a.noteRuntimeFailure(errors.New("private-secret-error"))
	if err := SaveRuntimeStatus(cfg, a, "pending", map[string]bool{"entry.example": true}, false, true); err != nil {
		t.Fatal(err)
	}
	s, err := ReadRuntimeStatus()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	for _, secret := range []string{cfg.Token, cfg.SSHKey, "private-secret-error"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("status leaked secret/error details")
		}
	}
	if !strings.Contains(s.ProtectedScope, "not a system-wide VPN") || s.Admission != "pending" || s.Failure == "" {
		t.Fatal("status overstated scope or concealed failure")
	}
	store, _ := NewTokenStore()
	s.At = time.Now().Add(-time.Hour).Unix()
	raw, _ = json.Marshal(s)
	if err := os.WriteFile(filepath.Join(store.Dir, "runtime-status.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := ReadRuntimeStatus(); err != nil || s.Running {
		t.Fatal("stale status claimed active client", err)
	}
}

func TestNonMuxCarrierRemainsOwnedWhileDraining(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	client := NewWithOptions(transport.NewWSTLS(transport.WSTLSOptions{}), Options{Mux: false})
	defer client.Close()
	owned, err := client.adoptConnection(left)
	if err != nil {
		t.Fatal(err)
	}
	client.Drain()
	if client.DrainComplete() {
		t.Fatal("nonmux active connection lost drain ownership")
	}
	go func() { buf := make([]byte, 4); _, _ = io.ReadFull(right, buf); _, _ = right.Write(buf) }()
	_ = owned.SetDeadline(time.Now().Add(time.Second))
	if _, err := owned.Write([]byte("live")); err != nil {
		t.Fatal("drain killed active nonmux transfer", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(owned, buf); err != nil {
		t.Fatal(err)
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	if !client.DrainComplete() {
		t.Fatal("finished nonmux connection still retained")
	}
}

func TestNetworkChangeRetiresButDoesNotKillActiveStreams(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	a := NewAdaptive("", transport.WSTLSOptions{}, "auto", time.Second)
	defer a.Close()
	cl := a.build(0)
	dials := 0
	cl.poolOnce.Do(func() { cl.pool = newMuxPool(echoSessionFactory(&dials), 1, time.Second) })
	stream, err := cl.getPool().Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	a.NetworkChanged()
	a.mu.Lock()
	retiredCount := len(a.retiredClients)
	a.mu.Unlock()
	if retiredCount != 1 {
		t.Fatal("network change lost active client ownership")
	}
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte("network-change")); err != nil {
		t.Fatal("network change killed old active stream", err)
	}
	buf := make([]byte, len("network-change"))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
}
