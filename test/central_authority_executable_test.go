package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"opentunnel/internal/authority"
	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/panel"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
)

func executableCertFiles(t *testing.T, dir, name string, cert tls.Certificate) (string, string) {
	t.Helper()
	certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefile.WriteNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})); err != nil {
		t.Fatal(err)
	}
	if err := privatefile.WriteNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func executableFreeEndpoint(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func startAuthorityFixtureProcess(t *testing.T, ctx context.Context, binary, state, configFile string, args ...string) {
	t.Helper()
	logFile, err := os.OpenFile(filepath.Join(state, "executable.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, append([]string{"-c", configFile}, args...)...)
	cmd.Env = append(os.Environ(), "TMPDIR="+state, "LOCALAPPDATA="+filepath.Join(state, "unused-client"), "OTU_AUTHORIZED_KEYS=", "ADMIN_USER=", "ADMIN_PASSWORD=")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = logFile.Close() })
}

func TestCentralAuthorityNativeExecutablesNeverUseRelayLocalDB(t *testing.T) {
	serverBinary, panelBinary := os.Getenv("OTU_TEST_SERVER_BINARY"), os.Getenv("OTU_TEST_PANEL_BINARY")
	if serverBinary == "" || panelBinary == "" {
		t.Skip("set staged native server/panel executable paths for process-level central-authority acceptance")
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	dir := t.TempDir()
	authorityDir := filepath.Join(dir, "authority")
	if err := privatefile.EnsureDir(authorityDir); err != nil {
		t.Fatal(err)
	}
	_, operator, _ := ed25519.GenerateKey(rand.Reader)
	poolID := serverpool.OperatorID(operator.Public().(ed25519.PublicKey))
	db, err := panel.Open(filepath.Join(authorityDir, "panel.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	info, err := db.BindServerPoolAuthentication(poolID, false, true)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := authorityTestCertificate(t)
	certPath, keyPath := executableCertFiles(t, authorityDir, "authority", serverCert)
	nodeCerts := []tls.Certificate{authorityTestCertificate(t), authorityTestCertificate(t)}
	inventory := authority.Nodes{Nodes: []authority.Node{{ID: "node-a", Pins: []string{protocol.PublicKeyPin(nodeCerts[0].Leaf)}}, {ID: "node-b", Pins: []string{protocol.PublicKeyPin(nodeCerts[1].Leaf)}}}}
	raw, _ := json.Marshal(inventory)
	inventoryPath := filepath.Join(authorityDir, "nodes.json")
	if err := privatefile.WriteNew(inventoryPath, raw); err != nil {
		t.Fatal(err)
	}
	apiAddr, panelAddr := executableFreeEndpoint(t), executableFreeEndpoint(t)
	panelConfig := filepath.Join(authorityDir, "server.toml")
	configuration := fmt.Sprintf("pool_id=%q\nrequire_channel_auth=true\nauthority_listen=%q\nauthority_cert=%q\nauthority_key=%q\nauthority_nodes=%q\n", poolID, apiAddr, certPath, keyPath, inventoryPath)
	if err := privatefile.WriteNew(panelConfig, []byte(configuration)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	startAuthorityFixtureProcess(t, ctx, panelBinary, authorityDir, panelConfig, "-listen", panelAddr)
	remote, err := authority.NewClient(authority.ClientOptions{URL: "https://" + apiAddr, PoolID: poolID, AuthorityID: info.AuthorityID, NodeID: "node-a", Certificate: nodeCerts[0], Pins: []string{protocol.PublicKeyPin(serverCert.Leaf)}})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := remote.Info(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native authority process did not authenticate node requests")
		}
		time.Sleep(50 * time.Millisecond)
	}
	nodes := []serverpool.Node{}
	for i := range 2 {
		state := filepath.Join(dir, inventory.Nodes[i].ID)
		if err := privatefile.EnsureDir(state); err != nil {
			t.Fatal(err)
		}
		nodeCert, nodeKey := executableCertFiles(t, state, "node", nodeCerts[i])
		inner := innerTestCert(t)
		innerCert, innerKey := executableCertFiles(t, state, "inner", inner)
		outer := innerTestCert(t)
		outerCert, outerKey := executableCertFiles(t, state, "outer", outer)
		addr := executableFreeEndpoint(t)
		cfgPath := filepath.Join(state, "server.toml")
		cfg := fmt.Sprintf("listen=%q\nhost=\"127.0.0.1\"\nh3=false\ncert_file=%q\nkey_file=%q\npool_id=%q\nrequire_inner_tls=true\nrequire_channel_auth=true\ninner_tls_cert=%q\ninner_tls_key=%q\nauthority_url=%q\nauthority_id=%q\nauthority_node_id=%q\nauthority_client_cert=%q\nauthority_client_key=%q\nauthority_pins=[%q]\nws_path=\"/stream\"\nallow_restricted_targets=true\n", addr, outerCert, outerKey, poolID, innerCert, innerKey, "https://"+apiAddr, info.AuthorityID, inventory.Nodes[i].ID, nodeCert, nodeKey, protocol.PublicKeyPin(serverCert.Leaf))
		if err := privatefile.WriteNew(cfgPath, []byte(cfg)); err != nil {
			t.Fatal(err)
		}
		startAuthorityFixtureProcess(t, ctx, serverBinary, state, cfgPath)
		nodes = append(nodes, serverpool.Node{ID: inventory.Nodes[i].ID, Name: inventory.Nodes[i].ID, Address: addr, Pins: []string{hex.EncodeToString(transport.FingerprintCert(outer.Certificate[0]))}, InnerTLSPins: []string{protocol.PublicKeyPin(inner.Leaf)}, WSPath: "/stream"})
	}
	now := time.Now()
	profile := serverpool.Profile{Name: "Native central authority fixture", AuthorityID: info.AuthorityID, IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ApprovalRequired: true, RequireChannelAuth: true, Nodes: nodes}
	if err := profile.Sign(operator, now); err != nil {
		t.Fatal(err)
	}
	selector, err := client.NewPoolSelector(profile)
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		if err := selector.Refresh(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native relay process did not forward verified pool capability")
		}
		time.Sleep(50 * time.Millisecond)
	}
	store, err := client.NewPoolTokenStore(poolID)
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.ClientConf{Pool: &profile, PoolNode: selector.Current, RequireChannelAuth: true}
	if err := client.EnrollPool(ctx, cfg, device, nil); err != nil {
		t.Fatal("native process enrollment", err)
	}
	if err := db.PeerStateAction(device.Token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("native-central-fixture"), 8192)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	target, err := parseAddrForTest(host, port)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		// Force each independent OS process, not a single selector's warm pool.
		one := profile
		one.Nodes = []serverpool.Node{node}
		if err := one.Sign(operator, now); err != nil {
			t.Fatal(err)
		}
		selectOne, err := client.NewPoolSelector(one)
		if err != nil {
			t.Fatal(err)
		}
		dialer := client.NewAdaptive("", transport.WSTLSOptions{}, "fast", 5*time.Second)
		dialer.UseTrustedPool(selectOne)
		dialer.EnableMux()
		conn, err := dialer.DialTunnel(ctx, target)
		if err != nil {
			dialer.Close()
			t.Fatal("native relay authenticated data", err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			dialer.Close()
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		conn.Close()
		dialer.Close()
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatal("native relay payload mismatch", err)
		}
		if _, err := os.Stat(filepath.Join(dir, node.ID, "panel.db")); !os.IsNotExist(err) {
			t.Fatal("remote executable opened a local approval DB")
		}
	}
	p, err := db.AccessPolicy(device.Token)
	if err != nil || p.UsedBytes < int64(2*len(payload)) || !p.ChannelVerified {
		t.Fatal("native processes did not share authoritative usage/identity", err)
	}
	t.Log("native authority plus two relay OS processes: isolated node credentials, signed pending enrollment, separate approval, exporter-bound data and no relay-local SQLite passed")
}
