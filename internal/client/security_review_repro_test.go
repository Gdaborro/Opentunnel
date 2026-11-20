//go:build windows && netenvfixture

package client

// Additional internal review reproductions, not release acceptance. All keys
// are generated in memory; HTTP is synthetic/loopback and executables are
// copied Go TEST binaries. No installed client, registry, or live fleet access.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/panel"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/version"
)

func requireSecurityReviewRepro(t *testing.T) {
	t.Helper()
	if os.Getenv("OTU_SECURITY_REVIEW_REPRO") != "1" {
		t.Skip("opt-in internal reproduction: set OTU_SECURITY_REVIEW_REPRO=1")
	}
}

func securityReviewGoCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	// Other checkouts and Windows CI do not have the operator's installation.
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go.exe")
	if info, err := os.Stat(goBinary); err != nil || !info.Mode().IsRegular() {
		t.Fatal("running test toolchain executable is unavailable")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate the reviewed source tree")
	}
	cmd := exec.CommandContext(t.Context(), goBinary, args...)
	cmd.Dir = filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	cmd.Env = append(withoutUpdateEnvironment(os.Environ()), "LOCALAPPDATA="+t.TempDir(), "GOTOOLCHAIN=local", "GOPROXY=off")
	return cmd
}

func securityReviewBundle(now time.Time) protocol.ReleaseBundle {
	return protocol.ReleaseBundle{
		Version: 1, Tag: "v1.1.99", Channel: "candidate", Sequence: 5,
		RolloutPercent: 100, SourceCommit: strings.Repeat("a", 40),
		Toolchain: "go1.27.4", BuildRecipe: "otu-repro-v1",
		MinimumVersion: "v1.1.10", RootVersion: 1,
		IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Artifacts: []protocol.ReleaseArtifact{{Name: updateAssetWin, Platform: "windows/amd64", SHA256: strings.Repeat("b", 64), Bytes: 4096}},
	}
}

func securityReviewFetch(t *testing.T, b protocol.ReleaseBundle) (signedBundle, error) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := protocol.ReleaseRoot{Version: b.RootVersion, Keys: []string{base64.StdEncoding.EncodeToString(pub)}, Threshold: 1, IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix()}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := json.Marshal([]protocol.RootSignature{{KeyID: protocol.ReleaseKeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.ReleaseBundleMessage(raw)))}})
	if err != nil {
		t.Fatal(err)
	}
	rel := &Release{TagName: b.Tag}
	for _, name := range []string{protocol.ReleaseBundleName, protocol.ReleaseBundleSignature} {
		rel.Assets = append(rel.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		}{Name: name, URL: "https://github.com/" + updateRepo + "/releases/download/" + b.Tag + "/" + name})
	}
	hc := &http.Client{Transport: bundleHTTPFixture(func(req *http.Request) (*http.Response, error) {
		data := raw
		if strings.HasSuffix(req.URL.Path, ".sig") {
			data = sig
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}, nil
	})}
	return fetchReleaseBundleWithRoot(t.Context(), hc, rel, b.Channel, root)
}

func TestSecurityReviewSignedMinimumVersionEnforced(t *testing.T) {
	requireSecurityReviewRepro(t)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	b := securityReviewBundle(time.Now())
	b.MinimumVersion = "v1.1.50"
	if !isNewer(version.Version, b.MinimumVersion) {
		t.Skip("reproduction needs a running version below the synthetic signed minimum")
	}
	if _, err := securityReviewFetch(t, b); err == nil {
		t.Fatalf("accepted signed target %s with minimum_version=%s on running %s; compatibility floor was ignored", b.Tag, b.MinimumVersion, version.Version)
	}
}

func TestSecurityReviewCorruptBundleCheckpointFailsClosed(t *testing.T) {
	requireSecurityReviewRepro(t)
	for _, mode := range []string{"invalid tag", "missing issuance time"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", t.TempDir())
			b := securityReviewBundle(time.Now())
			if err := saveBundleCheckpoint(b); err != nil {
				t.Fatal(err)
			}
			digest, err := b.Digest()
			if err != nil {
				t.Fatal(err)
			}
			checkpoint := bundleCheckpoint{Channel: b.Channel, Sequence: b.Sequence, Tag: b.Tag, Digest: digest, IssuedAt: b.IssuedAt}
			b.Sequence++
			if mode == "invalid tag" {
				checkpoint.Tag = "not-a-version"
				b.Tag = "v1.1.11"
			} else {
				checkpoint.IssuedAt = 0
				b.IssuedAt -= 3600
			}
			if err := b.Validate(time.Now()); err != nil {
				t.Fatal("replacement bundle fixture invalid", err)
			}
			store, err := NewTokenStore()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.Dir, "release-bundle-checkpoint-"+b.Channel+".json")
			raw, err := json.Marshal(checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing issuance time" {
				var fields map[string]any
				if err := json.Unmarshal(raw, &fields); err != nil {
					t.Fatal(err)
				}
				delete(fields, "issued_at")
				raw, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := privatefile.Write(path, raw); err != nil {
				t.Fatal(err)
			}
			if _, err := securityReviewFetch(t, b); err == nil {
				t.Fatalf("%s checkpoint was replaced and rollback accepted: tag=%s issued_at=%d", mode, b.Tag, b.IssuedAt)
			}
		})
	}
}

// If a root-chain file is omitted by a partial restore, activeReleaseRoot falls
// back to root 1. This exercises the checked-root input/parser/checkpoint path
// to show that a remaining root-2 bundle checkpoint cannot detect that fallback.
func TestSecurityReviewBundleCheckpointRejectsRootRollback(t *testing.T) {
	requireSecurityReviewRepro(t)
	t.Setenv("LOCALAPPDATA", t.TempDir())
	b := securityReviewBundle(time.Now())
	b.RootVersion = 2
	if _, err := securityReviewFetch(t, b); err != nil {
		t.Fatal("synthetic root-2 bundle checkpoint failed", err)
	}
	b.RootVersion = 1
	b.Sequence++
	b.Tag = "v1.1.100"
	if _, err := securityReviewFetch(t, b); err == nil {
		t.Fatal("persisted root-2 bundle checkpoint allowed new authorization by a root-1 trust input after root-chain loss")
	}
}

func TestSecurityReviewReleaseToolParsesClientSignatureEnvelope(t *testing.T) {
	requireSecurityReviewRepro(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b := securityReviewBundle(now)
	root := protocol.ReleaseRoot{Version: 1, Keys: []string{base64.StdEncoding.EncodeToString(pub)}, Threshold: 1, IssuedAt: now.Add(-time.Hour).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix()}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	signatures := []protocol.RootSignature{{KeyID: protocol.ReleaseKeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.ReleaseBundleMessage(raw)))}}
	if _, err := protocol.VerifyBundleWithRoot(raw, signatures, root, now); err != nil {
		t.Fatal("client envelope fixture invalid", err)
	}
	sigRaw, err := json.Marshal(signatures)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, protocol.ReleaseBundleName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, protocol.ReleaseBundleSignature), sigRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := securityReviewGoCommand(t, "run", "-tags=netenvfixture", "./tools/releasebundle", "--verify", "--directory", dir, "--tag", b.Tag)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("synthetic signer unexpectedly trusted by the embedded release-tool key")
	}
	// A synthetic signer MUST be refused, but the supported client envelope
	// should first parse. Here it is refused as a format that the tool cannot read.
	if strings.Contains(string(output), "detached signature encoding invalid") {
		t.Fatalf("release verifier cannot parse the signature envelope supported by the client, even at root 1: %s", output)
	}
	if !strings.Contains(string(output), "signature") {
		t.Fatalf("release verifier failed for an unrelated reason: %s", output)
	}
}

func TestSecurityReviewBuilderRequiresCoordinatedInventory(t *testing.T) {
	requireSecurityReviewRepro(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("synthetic metadata only; no binaries or source evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := securityReviewGoCommand(t, "run", "-tags=netenvfixture", "./tools/releasebundle", "--directory", dir, "--tag", "v1.1.99", "--sequence", "1", "--source-commit", strings.Repeat("a", 40), "--toolchain", "go99.99.99", "--minimum-version", "v1.1.10")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("public builder accepted metadata-only inventory with no required binaries, source archive, SBOM or BUILD-PROVENANCE evidence and arbitrary source/toolchain declarations: %s", output)
	}
	if !strings.Contains(string(output), "inventory") && !strings.Contains(string(output), "provenance") && !strings.Contains(string(output), "artifact") && !strings.Contains(string(output), "source") && !strings.Contains(string(output), "toolchain") {
		t.Fatalf("builder failed for an unrelated reason: %s", output)
	}
}

// This subprocess confines x509 fallback roots and all simulated GitHub TLS to
// one TEST process. The SOCKS fixture never dials the requested remote address.
func TestSecurityReviewMissingStagedFeedFailsClosed(t *testing.T) {
	requireSecurityReviewRepro(t)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSecurityReviewMissingFeedProbe$", "-test.v")
	cmd.Env = append(withoutUpdateEnvironment(os.Environ()), "OTU_SECURITY_REVIEW_ROLE=missing-feed", "GODEBUG=x509usefallbackroots=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated staged-feed reproduction: %v\n%s", err, output)
	}
}

func TestSecurityReviewMissingFeedProbe(t *testing.T) {
	if os.Getenv("OTU_SECURITY_REVIEW_ROLE") != "missing-feed" {
		return
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	b := securityReviewBundle(time.Now())
	b.ExpiresAt = time.Now().Unix() + 2
	if _, err := securityReviewFetch(t, b); err != nil {
		t.Fatal("could not prime a synthetically signed checkpoint", err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"api.github.com", "github.com"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	x509.SetFallbackRoots(roots)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+updateRepo+"/releases" {
			http.Error(w, "fixture forbids unexpected path", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "[]")
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()
	socks := securityReviewLoopbackSOCKS(t, srv.Listener.Addr().String())
	setHostileMode(true) // force the loopback-only SOCKS leg, never direct GitHub
	t.Cleanup(func() { setHostileMode(false) })
	time.Sleep(time.Until(time.Unix(b.ExpiresAt, 0)) + 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rel, err := CheckUpdateChannel(ctx, socks, "candidate")
	if rel == nil && err == nil {
		t.Fatalf("unsigned empty staged feed returned success despite an expired signed checkpoint: expires=%d now=%d status=%q", b.ExpiresAt, time.Now().Unix(), CurrentUpdateStatus().State)
	}
}

func securityReviewLoopbackSOCKS(t *testing.T, target string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var buf [262]byte
				if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[0] != 5 || buf[1] != 1 || buf[3] != 3 {
					return
				}
				if _, err := io.ReadFull(c, buf[:1]); err != nil {
					return
				}
				n := int(buf[0])
				if _, err := io.ReadFull(c, buf[:n+2]); err != nil {
					return
				}
				host := string(buf[:n])
				if (host != "api.github.com" && host != "github.com") || buf[n] != 1 || buf[n+1] != 187 {
					return // only the expected synthetic HTTPS destination is admitted
				}
				up, err := net.DialTimeout("tcp", target, 3*time.Second) // target is loopback
				if err != nil {
					return
				}
				defer up.Close()
				if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSecurityReviewRecoveryDoesNotRollbackLiveReplacement(t *testing.T) {
	requireSecurityReviewRepro(t)
	dir := t.TempDir()
	t.Setenv("LOCALAPPDATA", filepath.Join(dir, "appdata"))
	store, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	updates := filepath.Join(store.Dir, "updates")
	if err := privatefile.EnsureDir(updates); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(os.Args[0]) // copied TEST executable, never an installed client
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "fixture.exe")
	backup := exe + ".old-review"
	if err := os.WriteFile(backup, source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, append(bytes.Clone(source), []byte("synthetic replacement marker")...), 0o700); err != nil {
		t.Fatal(err)
	}
	previous, err := fileDigest(backup)
	if err != nil {
		t.Fatal(err)
	}
	current, err := fileDigest(exe)
	if err != nil {
		t.Fatal(err)
	}
	tx := updateTransaction{Version: 1, Executable: exe, Staged: exe + ".new-review.exe", Backup: backup, SHA256: current, PreviousSHA256: previous, Parent: 2147483646, Helper: 2147483645, Token: strings.Repeat("a", 43), Args: []string{"-test.run=^TestSecurityReviewRecoveryProbe$"}, ReadyFile: filepath.Join(updates, "ready-review"), StartedAt: time.Now().Unix()}
	journal := filepath.Join(updates, updateJournalName)
	raw, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefile.WriteNew(journal, raw); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	live := exec.CommandContext(ctx, exe, "-test.run=^TestSecurityReviewRecoveryProbe$")
	live.Env = append(withoutUpdateEnvironment(os.Environ()), "OTU_SECURITY_REVIEW_ROLE=live", "OTU_UPDATE_READY_FILE="+tx.ReadyFile, "OTU_UPDATE_READY_TOKEN="+tx.Token)
	out, err := live.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Process.Kill(); _ = live.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "live" {
		t.Fatal("live replacement fixture did not initialize", err, line)
	}
	probe := exec.CommandContext(ctx, exe, "-test.run=^TestSecurityReviewRecoveryProbe$")
	probe.Env = append(withoutUpdateEnvironment(os.Environ()), "OTU_SECURITY_REVIEW_ROLE=recover")
	output, err := probe.CombinedOutput()
	if err != nil {
		t.Fatal("recovery probe process failed", err, string(output))
	}
	failed, err := filepath.Glob(exe + ".failed-*")
	if err != nil {
		t.Fatal(err)
	}
	images := append([]string{exe}, failed...)
	alive, err := updateProcessAlive(live.Process.Pid, images...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "restarted=true") && alive {
		t.Fatalf("rolled back and restarted the previous executable while replacement PID %d remained alive; probe=%q", live.Process.Pid, output)
	}
	if !strings.Contains(string(output), ErrUpdateInProgress.Error()) {
		t.Fatalf("did not explicitly refuse recovery of the live replacement: %q", output)
	}
}

func TestSecurityReviewRecoveryProbe(t *testing.T) {
	switch os.Getenv("OTU_SECURITY_REVIEW_ROLE") {
	case "live":
		if err := ReportUpdateReady(); err != nil {
			fmt.Fprintln(os.Stdout, "readiness error:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, "live")
		time.Sleep(20 * time.Second)
		os.Exit(0)
	case "recover":
		restarted, err := RecoverPendingUpdate()
		fmt.Fprintf(os.Stdout, "restarted=%t err=%v\n", restarted, err)
		os.Exit(0)
	}
}

func TestSecurityReviewExecutableBackupRejectsDanglingLink(t *testing.T) {
	requireSecurityReviewRepro(t)
	dir := t.TempDir()
	exe, staged, backup := filepath.Join(dir, "current"), filepath.Join(dir, "staged"), filepath.Join(dir, "backup")
	if err := os.WriteFile(exe, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "absent"), backup); err != nil {
		t.Skip("host cannot create a fixture symlink without privileges; no elevation attempted", err)
	}
	if err := replaceExecutable(exe, staged, backup, func() error { return nil }); err == nil {
		t.Fatal("new-only executable backup overwrote a pre-existing dangling symlink")
	}
	if info, err := os.Lstat(backup); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("existing backup object was changed", err)
	}
}

func TestSecurityReviewDatabaseBackupNewOnlyAndWALConsistent(t *testing.T) {
	requireSecurityReviewRepro(t)
	dir := t.TempDir()
	db, err := panel.Open(filepath.Join(dir, "synthetic.db"), 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE review_counter(id INTEGER PRIMARY KEY, value INTEGER NOT NULL); INSERT INTO review_counter VALUES(1,0),(2,0)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	writerDone := make(chan error, 1)
	go func() {
		for n := 1; ctx.Err() == nil; n++ {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				writerDone <- err
				return
			}
			if _, err := tx.ExecContext(ctx, `UPDATE review_counter SET value=?`, n); err != nil {
				_ = tx.Rollback()
				writerDone <- err
				return
			}
			if err := tx.Commit(); err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()
	defer func() {
		cancel()
		if err := <-writerDone; err != nil && !errors.Is(err, context.Canceled) {
			t.Error("synthetic concurrent writer failed", err)
		}
	}()
	destination := filepath.Join(dir, "snapshot.db")
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- db.BackupDatabase(ctx, destination) }()
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent new-only publication: got %d successes, want exactly 1", successes)
	}
	copy, err := panel.Open(destination, 14) // only the synthetic snapshot
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	var low, high int
	if err := copy.QueryRow(`SELECT MIN(value),MAX(value) FROM review_counter`).Scan(&low, &high); err != nil {
		t.Fatal(err)
	}
	if low != high {
		t.Fatalf("torn WAL snapshot: min=%d max=%d", low, high)
	}
	t.Logf("snapshot is transaction-consistent (counter=%d), with one successful no-replace publication", low)
}
