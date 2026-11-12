package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/netutil"
)

// Explicit local-only UI acceptance fixture. It uses a new temporary database,
// synthetic identities and a throwaway setup token; no production configuration,
// keys, listeners or installed-client state are loaded. Disabled in normal CI.
func TestLocalPanelBrowserLab(t *testing.T) {
	addr := os.Getenv("OTU_BROWSER_LAB_ADDR")
	if addr == "" {
		t.Skip("set OTU_BROWSER_LAB_ADDR to an explicit free loopback endpoint")
	}
	if err := netutil.LoopbackEndpoint(addr); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTU_SETUP_TOKEN", "synthetic-browser-fixture-setup-only")
	db, err := Open(filepath.Join(t.TempDir(), "browser-fixture.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct{ token, name, status string }{
		{"browser-fixture-approved-token-0001", "Synthetic workstation", "approved"},
		{"browser-fixture-pending-token-0002", "Synthetic pending device", "pending"},
	} {
		if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,?,?, ?,datetime('now'),datetime('now'),?,'browser-fixture')`, peer.token, peer.token, peer.name, peer.status, string(ssh.MarshalAuthorizedKey(key))); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetSettings(map[string]string{"kill_switch": "1", "kill_switch_reason": "Synthetic browser acceptance fixture"}); err != nil {
		t.Fatal(err)
	}
	handler := New(db, NewAuth(db), false).Handler()
	stop := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	mux.HandleFunc("POST /__browser_lab/stop", func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		once.Do(func() { close(stop) })
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	defer srv.Close()
	exited := make(chan error, 1)
	go func() { exited <- srv.Serve(ln) }()
	fmt.Printf("Isolated browser lab ready on http://localhost:%s/admin (synthetic data only)\n", func() string { _, port, _ := net.SplitHostPort(addr); return port }())
	select {
	case <-stop:
	case <-t.Context().Done():
	case err := <-exited:
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	}
}
