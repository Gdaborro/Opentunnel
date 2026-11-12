package reality

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

func freeEndpoint(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func labBinary(t *testing.T) (string, string) {
	t.Helper()
	path := os.Getenv("OTU_TEST_XRAY")
	if path == "" {
		t.Skip("set OTU_TEST_XRAY to the pinned patched companion for loopback REALITY tests")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("companion binary unavailable")
	}
	sum := sha256.Sum256(raw)
	return path, hex.EncodeToString(sum[:])
}

func localCover(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cover.test"}, DNSNames: []string{"cover.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "cover fixture") }))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func startLab(t *testing.T, binary, digest string, data []byte, mode, listen, target string) *Supervisor {
	t.Helper()
	s, err := Start(t.Context(), ProcessOptions{Executable: binary, SHA256: digest, Mode: mode, Config: data, Listen: listen, Target: target, StateDir: t.TempDir(), ReadyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("%s startup: %v", mode, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestREALITYAuthenticatedTunnelAndConfinement(t *testing.T) {
	binary, digest := labBinary(t)
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
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'fixture','approved',datetime('now'),datetime('now'),?,'lab')`, device.Token, pub); err != nil {
		t.Fatal(err)
	}
	var ingress atomic.Int64
	var activeIngress atomic.Int64
	relayHandler := server.WithIngress(server.Handler(server.Options{PanelDB: db, AllowRestrictedTargets: true}), server.IngressCarrier)
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ingress.Add(1)
		activeIngress.Add(1)
		defer activeIngress.Add(-1)
		relayHandler.ServeHTTP(w, r)
	}))
	defer relay.Close()
	cover := localCover(t)
	priv, password, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	uuid, _ := GenerateUUID()
	short, _ := GenerateShortID()
	endpoint := freeEndpoint(t)
	target := relay.Listener.Addr().String()
	serverData, err := ServerJSON(ServerParams{Listen: endpoint, Target: target, CoverTarget: cover.Listener.Addr().String(), ServerName: "cover.test", PrivateKey: priv, UUIDs: []string{uuid}, ShortIDs: []string{short}, AllowLoopbackCover: true})
	if err != nil {
		t.Fatal(err)
	}
	serverProcess := startLab(t, binary, digest, serverData, "server", endpoint, target)
	listen := freeEndpoint(t)
	user, pass, _ := LocalAuth()
	p := Profile{Version: 1, Endpoint: endpoint, ServerName: "cover.test", UUID: uuid, Password: password, ShortID: short, Target: target}
	clientData, err := ClientJSON(p, listen, user, pass)
	if err != nil {
		t.Fatal(err)
	}
	companion := startLab(t, binary, digest, clientData, "client", listen, target)
	carrier := transport.NewCarrier(transport.CarrierOptions{SOCKSAddr: listen, Target: target, SOCKSUser: user, SOCKSPassword: pass, Ready: companion.WaitReady, DialTimeout: 5 * time.Second})
	cl := client.NewWithOptions(carrier, client.Options{Token: device.Token, Mux: true, DialTimeout: 5 * time.Second})
	defer cl.Close()
	bulk := bytes.Repeat([]byte("reality-fixture"), 1<<16)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bulk) }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	addr, err := protocol.ParseAddress(host, mustPort(port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	c, err := cl.DialTunnel(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
	data, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || !bytes.HasSuffix(data, bulk) {
		t.Fatalf("authenticated REALITY bulk failed: %v bytes=%d", err, len(data))
	}
	// In-band status remains available while the global data switch is on.
	db.SetKillSwitch(true)
	if resp, err := cl.CtrlExchange(ctx, protocol.CtrlRequest{Op: "status"}); err != nil || resp.Status != "approved" {
		t.Fatal("REALITY control channel lost under kill switch", err)
	}
	if c, err := cl.DialTunnel(ctx, addr); err == nil {
		_ = c.Close()
		t.Fatal("REALITY data bypassed kill switch")
	}
	db.SetKillSwitch(false)
	if resp, err := cl.CtrlExchange(ctx, protocol.CtrlRequest{Op: "status"}); err != nil || !resp.OK {
		t.Fatal("control channel failed after kill switch release", err)
	}
	if ingress.Load() == 0 {
		t.Fatal("no authenticated tunnel reached the relay")
	}
	if seconds, err := strconv.Atoi(os.Getenv("OTU_REALITY_SOAK_SECONDS")); err == nil && seconds > 0 {
		start := time.Now()
		iterations := 0
		var transferred int64
		for time.Since(start) < time.Duration(seconds)*time.Second {
			if iterations > 0 && iterations%10 == 0 {
				_ = cl.Close()
				t.Logf("REALITY soak recreate: iteration=%d live_relay_requests=%d", iterations, activeIngress.Load())
				deadline := time.Now().Add(2 * time.Second)
				for activeIngress.Load() != 0 && time.Now().Before(deadline) {
					time.Sleep(20 * time.Millisecond)
				}
				if activeIngress.Load() != 0 {
					t.Fatal("pool close left an orphaned REALITY relay session")
				}
				cl = client.NewWithOptions(carrier, client.Options{Token: device.Token, Mux: true, DialTimeout: 5 * time.Second})
			}
			qctx, qcancel := context.WithTimeout(t.Context(), 10*time.Second)
			stream, err := cl.DialTunnel(qctx, addr)
			qcancel()
			if err != nil {
				t.Fatal("REALITY soak dial", err)
			}
			_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
			_, _ = io.WriteString(stream, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
			payload, err := io.ReadAll(stream)
			_ = stream.Close()
			if err != nil || !bytes.HasSuffix(payload, bulk) {
				t.Fatal("REALITY soak transfer", err)
			}
			iterations++
			transferred += int64(len(bulk))
			time.Sleep(time.Second)
		}
		t.Logf("REALITY TCP soak: duration=%s iterations=%d payload_bytes=%d", time.Since(start).Round(time.Second), iterations, transferred)
		_ = cl.Close()
		cl = client.NewWithOptions(carrier, client.Options{Token: device.Token, Mux: true, DialTimeout: 5 * time.Second})
		ctx = t.Context()
	}
	// Local SOCKS must require its private per-run credential.
	unauth, _ := proxy.SOCKS5("tcp", listen, nil, &net.Dialer{Timeout: time.Second})
	if c, err := unauth.(proxy.ContextDialer).DialContext(ctx, "tcp", target); err == nil {
		_ = c.Close()
		t.Fatal("unauthenticated local proxy admitted traffic")
	}
	// The valid client must reject arbitrary destinations before the carrier.
	valid, _ := proxy.SOCKS5("tcp", listen, &proxy.Auth{User: user, Password: pass}, &net.Dialer{Timeout: time.Second})
	for _, dst := range []string{origin.Listener.Addr().String(), "203.0.113.1:443", "127.0.0.1:22"} {
		qctx, qcancel := context.WithTimeout(t.Context(), 2*time.Second)
		c, err := valid.(proxy.ContextDialer).DialContext(qctx, "tcp", dst)
		qcancel()
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = c.Write([]byte("forbidden"))
			var b [1]byte
			_, err = c.Read(b[:])
			_ = c.Close()
		}
		if err == nil {
			t.Fatal("non-fixed destination passed client policy")
		}
	}
	// Wrong REALITY user cannot reach the opentunnel handshake.
	bad := p
	bad.UUID, _ = GenerateUUID()
	badListen := freeEndpoint(t)
	badData, _ := ClientJSON(bad, badListen, user, pass)
	badProcess := startLab(t, binary, digest, badData, "client", badListen, target)
	badHTTP, err := transport.NewCarrierHTTPClient(transport.CarrierOptions{SOCKSAddr: badListen, Target: target, SOCKSUser: user, SOCKSPassword: pass, Ready: badProcess.WaitReady, DialTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer badHTTP.CloseIdleConnections()
	if resp, err := badHTTP.Get("http://" + target + "/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("wrong VLESS identity reached ingress")
	}
	for _, kind := range []string{"password", "short ID"} {
		wrong := p
		if kind == "password" {
			_, wrong.Password, _ = GenerateKey()
		} else {
			wrong.ShortID, _ = GenerateShortID()
		}
		wrongListen := freeEndpoint(t)
		config, _ := ClientJSON(wrong, wrongListen, user, pass)
		proc := startLab(t, binary, digest, config, "client", wrongListen, target)
		probe, err := transport.NewCarrierHTTPClient(transport.CarrierOptions{SOCKSAddr: wrongListen, Target: target, SOCKSUser: user, SOCKSPassword: pass, Ready: proc.WaitReady, DialTimeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := probe.Get("http://" + target + "/"); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("wrong REALITY %s reached ingress", kind)
		}
		probe.CloseIdleConnections()
		_ = proc.Close()
	}
	// Ordinary TLS exposes only the chosen fallback identity, not an
	// authenticated tunnel. Pin to our synthetic cover certificate here.
	fallback, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", endpoint, &tls.Config{ServerName: "cover.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal("unknown-client fallback failed", err)
	}
	if certs := fallback.ConnectionState().PeerCertificates; len(certs) == 0 || certs[0].Subject.CommonName != "cover.test" {
		_ = fallback.Close()
		t.Fatal("fallback did not match cover identity")
	}
	_ = fallback.Close()
	// Server-side confinement is independent of a compliant client. Test an
	// intentionally altered LAB-only client config that routes every target.
	var attack document
	_ = json.Unmarshal(clientData, &attack)
	attackListen := freeEndpoint(t)
	aHost, aPort, _ := net.SplitHostPort(attackListen)
	attack.Inbounds[0].Listen = aHost
	attack.Inbounds[0].Port = mustPort(aPort)
	attack.Routing.Rules = []rule{{Type: "field", Inbound: []string{"otu-local"}, Network: "tcp", Outbound: "reality"}}
	attackData, _ := json.Marshal(attack)
	if ValidateClientJSON(attackData, attackListen, target) == nil {
		t.Fatal("production validator admitted attack configuration")
	}
	attackProcess := startAttackFixture(t, binary, digest, attackData, attackListen)
	_ = attackProcess
	attacker, _ := proxy.SOCKS5("tcp", attackListen, &proxy.Auth{User: user, Password: pass}, &net.Dialer{Timeout: time.Second})
	qctx, qcancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer qcancel()
	ac, err := attacker.(proxy.ContextDialer).DialContext(qctx, "tcp", origin.Listener.Addr().String())
	if err == nil {
		_ = ac.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(ac, "GET / HTTP/1.0\r\nHost: forbidden\r\n\r\n")
		var b [1]byte
		_, err = ac.Read(b[:])
		_ = ac.Close()
	}
	if err == nil {
		t.Fatal("server allowed a modified client's arbitrary target")
	}
	// Killing the owned client triggers bounded restart; closing the
	// supervisor frees the listener and reaps its child.
	companion.mu.Lock()
	proc := companion.process
	companion.mu.Unlock()
	if proc == nil {
		t.Fatal("missing owned child")
	}
	_ = proc.Process.Kill()
	deadline := time.Now().Add(5 * time.Second)
	for {
		companion.mu.Lock()
		changed := companion.process != nil && companion.process != proc && companion.ready
		companion.mu.Unlock()
		if changed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("companion did not restart")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := companion.Close(); err != nil {
		t.Fatal(err)
	}
	if ln, err := net.Listen("tcp", listen); err != nil {
		t.Fatal("owned listener remained after teardown")
	} else {
		_ = ln.Close()
	}
	_ = serverProcess
	_ = cl.Close()
	t.Logf("REALITY lab: authenticated %d-byte payload, wrong user/local auth rejection, client/server fixed-target checks and child restart/reaping passed", len(bulk))
}

func mustPort(s string) int {
	var n int
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// This test-only helper deliberately bypasses the production validator so a
// hostile client can be used to test SERVER enforcement. Never exported.
func startAttackFixture(t *testing.T, binary, digest string, config []byte, listen string) *Supervisor {
	t.Helper()
	dir := t.TempDir()
	_ = privatefile.EnsureDir(dir)
	s := &Supervisor{o: ProcessOptions{SHA256: digest, Listen: listen, Config: config, ReadyTimeout: 5 * time.Second}, dir: dir, started: make(chan error, 1), done: make(chan struct{})}
	s.ctx, s.cancel = context.WithCancel(t.Context())
	name := "lab-attack"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	s.executable = filepath.Join(dir, name)
	s.config = filepath.Join(dir, "attack.json")
	if err := stageExecutable(binary, s.executable, digest); err != nil {
		t.Fatal(err)
	}
	if err := privatefile.WriteNew(s.config, config); err != nil {
		t.Fatal(err)
	}
	s.remove = func() { _ = os.Remove(s.config); _ = os.Remove(s.executable) }
	go s.loop()
	select {
	case err := <-s.started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		s.cancel()
		t.Fatal("lab attack readiness")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
