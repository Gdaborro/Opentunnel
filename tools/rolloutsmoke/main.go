// rolloutsmoke checks staged server/panel executables with synthetic identity,
// isolated temporary state and loopback listeners only. It does not deploy,
// change operational policy or connect to a production relay.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/panel"
	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

func main() {
	dir := flag.String("binary-dir", "", "absolute private staged directory containing server and panel")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(*dir) {
		fmt.Fprintln(os.Stderr, "use -binary-dir ABSOLUTE_STAGED_DIRECTORY")
		os.Exit(2)
	}
	if err := run(*dir); err != nil {
		fmt.Fprintln(os.Stderr, "isolated release smoke:", err)
		os.Exit(1)
	}
}

func freeEndpoint() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ln.Addr().String(), nil
}

func run(dir string) error {
	if runtime.GOOS != "linux" {
		return errors.New("native staged Linux smoke is Linux-only")
	}
	state, err := os.MkdirTemp("", "otu-release-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(state) // only the private directory created by this fixture
	os.Setenv("LOCALAPPDATA", filepath.Join(state, "client"))
	store, err := client.NewTokenStore()
	if err != nil {
		return err
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		return err
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		return err
	}
	db, err := panel.Open(filepath.Join(state, "panel.db"), 14)
	if err != nil {
		return err
	}
	if _, err = db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey,auth_epoch) VALUES(?,'synthetic-smoke','approved',datetime('now'),datetime('now'),?,'synthetic-smoke')`, device.Token, pub); err != nil {
		db.Close()
		return err
	}
	if err = panel.NewAuth(db).EnsureAdmin("synthetic-smoke", "Synthetic-smoke-password-only"); err != nil {
		db.Close()
		return err
	}
	if err = db.Close(); err != nil {
		return err
	}
	serverAddr, err := freeEndpoint()
	if err != nil {
		return err
	}
	panelAddr, err := freeEndpoint()
	if err != nil {
		return err
	}
	certFile, keyFile := filepath.Join(state, "cert.pem"), filepath.Join(state, "key.pem")
	cert, fp, err := transport.LoadOrCreateCert(certFile, keyFile, "127.0.0.1")
	if err != nil {
		return err
	}
	config := fmt.Sprintf("listen = %q\nhost = \"127.0.0.1\"\nh3 = false\ncert_file = %q\nkey_file = %q\nallow_restricted_targets = true\nauto_approve = false\n", serverAddr, certFile, keyFile)
	configPath := filepath.Join(state, "server.toml")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	children := []*exec.Cmd{}
	defer func() {
		for _, c := range children {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	}()
	for _, target := range []struct {
		name string
		args []string
	}{
		{"otu-panel-linux-amd64", []string{"-c", configPath, "-listen", panelAddr}},
		{"otu-server-linux-amd64", []string{"-c", configPath}},
	} {
		path := filepath.Join(dir, target.name)
		v := exec.CommandContext(ctx, path, "--version")
		out, err := v.Output()
		kind := "server"
		if strings.Contains(target.name, "panel") {
			kind = "panel"
		}
		if err != nil || strings.TrimSpace(string(out)) != "opentunnel "+kind+" "+version.Version {
			return errors.New("staged executable version mismatch")
		}
		c := exec.CommandContext(ctx, path, target.args...)
		c.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + state, "TMPDIR=" + state, "LOCALAPPDATA=" + filepath.Join(state, "client"), "OTU_PANEL_UPSTREAM=http://" + panelAddr}, "OTU_AUTHORIZED_KEYS="+filepath.Join(state, "unused-authorized-keys"))
		c.Stdout, c.Stderr = io.Discard, io.Discard
		if err := c.Start(); err != nil {
			return err
		}
		children = append(children, c)
	}
	for _, addr := range []string{panelAddr, serverAddr} {
		deadline := time.Now().Add(15 * time.Second)
		for {
			c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				return errors.New("staged listener readiness timeout")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, cert.Certificate[0]) {
			return errors.New("synthetic relay pin mismatch")
		}
		return nil
	}}}}
	defer hc.CloseIdleConnections()
	base := "https://" + serverAddr
	resp, err := hc.Get(base + "/admin/api/stats")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		return errors.New("admin gate smoke failed")
	}
	login, _ := json.Marshal(map[string]string{"username": "synthetic-smoke", "password": "Synthetic-smoke-password-only"})
	resp, err = hc.Post(base+"/admin/api/login", "application/json", bytes.NewReader(login))
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("synthetic panel login failed")
	}
	resp, err = hc.Get(base + "/admin/api/stats")
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("authenticated panel smoke failed")
	}
	bulk := bytes.Repeat([]byte("synthetic-release-payload"), 1<<18)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bulk) }))
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	var n int
	fmt.Sscan(port, &n)
	address, err := protocol.ParseAddress(host, n)
	if err != nil {
		return err
	}
	cl := client.NewWithOptions(transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: serverAddr, Fingerprint: fp}), client.Options{Token: device.Token, Mux: true, DialTimeout: 5 * time.Second})
	defer cl.Close()
	for range 3 {
		stream, err := cl.DialTunnel(ctx, address)
		if err != nil {
			return err
		}
		_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = io.WriteString(stream, "GET / HTTP/1.0\r\nHost: synthetic\r\n\r\n")
		if err != nil {
			stream.Close()
			return err
		}
		data, err := io.ReadAll(io.LimitReader(stream, int64(len(bulk))+4096))
		_ = stream.Close()
		if err != nil || !bytes.HasSuffix(data, bulk) {
			return errors.New("staged authenticated bulk transfer failed")
		}
	}
	control, err := cl.CtrlExchange(ctx, protocol.CtrlRequest{Op: "status"})
	if err != nil || control.Status != "approved" {
		return errors.New("staged control channel failed")
	}
	fmt.Printf("staged %s Linux executables: private startup, admin gate/login, authenticated control and %d payload bytes passed\n", version.Version, len(bulk)*3)
	fmt.Println("synthetic certificate pin:", hex.EncodeToString(transport.FingerprintCert(cert.Certificate[0])))
	return nil
}
