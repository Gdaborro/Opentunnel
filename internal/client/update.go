package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

const (
	updateRepo     = "Gdaborro/Opentunnel"
	updateAssetWin = "otu-client-windows-amd64.exe"
	updateCheckGap = 6 * time.Hour
)

// Release is the subset of the GitHub Releases API we consume.
type Release struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// LatestRelease fetches the newest published release (public repo, no auth).
// socksAddr is the client's own SOCKS proxy (usually 127.0.0.1:1080); when
// set, update traffic prefers a direct connection and falls back to the
// tunnel, so updates keep working on networks that block github.com.
func LatestRelease(ctx context.Context, socksAddr string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.github.com/repos/"+updateRepo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", transport.BrowserUA)
	cl := updateClient(socksAddr)
	defer cl.CloseIdleConnections()
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("auto-update: release metadata exceeds 1 MiB")
	}
	var rel Release
	if err := json.Unmarshal(data, &rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

var verRe = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`)

// parseVersion extracts major/minor/patch from a tag like "v0.9.1".
func parseVersion(s string) (major, minor, patch int, ok bool) {
	m := verRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0, false
	}
	a, ea := strconv.Atoi(m[1])
	b, eb := strconv.Atoi(m[2])
	c, ec := strconv.Atoi(m[3])
	if ea != nil || eb != nil || ec != nil {
		return 0, 0, 0, false
	}
	return a, b, c, true
}

// isNewer reports whether remoteTag is strictly newer than current.
func isNewer(current, remoteTag string) bool {
	cMaj, cMin, cPat, ok1 := parseVersion(current)
	rMaj, rMin, rPat, ok2 := parseVersion(remoteTag)
	if !ok1 || !ok2 {
		return false
	}
	switch {
	case rMaj != cMaj:
		return rMaj > cMaj
	case rMin != cMin:
		return rMin > cMin
	default:
		return rPat > cPat
	}
}

// expectedSHA256 extracts a "sha256: <hex>" line from release notes.
func expectedSHA256(body string) string {
	for _, line := range strings.Split(body, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(l, "sha256:") {
			sum := strings.TrimSpace(strings.TrimPrefix(l, "sha256:"))
			if len(sum) == 64 {
				if _, err := hex.DecodeString(sum); err == nil {
					return sum
				}
			}
		}
	}
	return ""
}

// CheckUpdate returns the release to install, or nil when up to date.
// Releases below MinUpdateTag are refused even when validly signed: the
// floor is what blocks a middleman from pinning the fleet to an old,
// genuinely-signed, known-vulnerable build (audit round three, N-3).
func CheckUpdate(ctx context.Context, socksAddr string) (*Release, error) {
	rel, err := LatestRelease(ctx, socksAddr)
	if err != nil {
		return nil, err
	}
	if _, _, _, ok := parseVersion(rel.TagName); !ok || !strings.HasPrefix(rel.TagName, "v") {
		return nil, errors.New("auto-update: release feed returned an invalid tag")
	}
	if belowMinTag(rel.TagName) {
		return nil, fmt.Errorf("auto-update: release %s is below the minimum supported version %s — refusing", rel.TagName, MinUpdateTag)
	}
	cl := updateClient(socksAddr)
	defer cl.CloseIdleConnections()
	if err := checkReleaseFreshness(ctx, cl, rel, version.Version); err != nil {
		return nil, err
	}
	if !isNewer(version.Version, rel.TagName) {
		return nil, nil
	}
	return rel, nil
}

// belowMinTag reports whether tag sorts strictly below MinUpdateTag.
// Unparseable tags are treated as below (refuse what cannot be checked).
func belowMinTag(tag string) bool {
	mMaj, mMin, mPat, ok1 := parseVersion(MinUpdateTag)
	rMaj, rMin, rPat, ok2 := parseVersion(tag)
	if !ok1 || !ok2 {
		return true
	}
	switch {
	case rMaj != mMaj:
		return rMaj < mMaj
	case rMin != mMin:
		return rMin < mMin
	default:
		return rPat < mPat
	}
}

// updateClient builds an HTTP client for update traffic: direct connection
// first (fast path), falling back to the tunnel's SOCKS proxy when direct
// is blocked (school/corporate firewalls that filter github.com). TLS stays
// end-to-end in both cases, so the fallback changes only the TCP path —
// integrity rests on the offline signatures, not the interceptable hash note.
func updateClient(socksAddr string) *http.Client {
	direct := &http.Transport{DialContext: (&net.Dialer{Timeout: 8 * time.Second}).DialContext, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
	if socksAddr == "" {
		return &http.Client{Transport: direct}
	}
	via := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socksDialContext(ctx, socksAddr, network, addr)
	}, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
	return &http.Client{Transport: &updateFallback{direct: direct, via: via}}
}

type updateFallback struct{ direct, via http.RoundTripper }

func (t *updateFallback) RoundTrip(req *http.Request) (*http.Response, error) {
	if HostileMode() {
		return t.via.RoundTrip(req)
	}
	ctx, cancel := context.WithCancel(req.Context())
	setupTimer := time.AfterFunc(45*time.Second, cancel)
	resp, err := t.direct.RoundTrip(req.Clone(ctx))
	setupTimer.Stop()
	// Keep the direct response context alive until its body is consumed.
	if err == nil && resp.StatusCode != 403 && resp.StatusCode != 451 && resp.StatusCode != 502 && resp.StatusCode != 503 && resp.StatusCode != 504 {
		resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	cancel()
	if req.Context().Err() != nil {
		return nil, req.Context().Err()
	}
	// Update requests are bodyless GETs. Do not replay arbitrary POSTs.
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("update fallback only supports GET/HEAD")
	}
	return t.via.RoundTrip(req)
}
func (t *updateFallback) CloseIdleConnections() {
	for _, tr := range []http.RoundTripper{t.direct, t.via} {
		if c, ok := tr.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error { defer b.cancel(); return b.ReadCloser.Close() }

// socksDialContext dials through a SOCKS5 proxy with ctx awareness.
func socksDialContext(ctx context.Context, socksAddr, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sd, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	cd, ok := sd.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("auto-update: SOCKS dialer lacks cancellable setup")
	}
	return cd.DialContext(ctx, network, addr)
}

// SelfUpdate downloads the release asset for this platform, verifies it
// (Ed25519 signature against the baked-in release key, then the sha256
// line from the notes), swaps the running binary, and re-executes. The
// signature is the trust anchor: release metadata, download URL and the
// sha256 line all ride channels a middlebox can rewrite, but a forged
// binary cannot produce a valid signature for the offline private key.
func SelfUpdate(ctx context.Context, rel *Release, socksAddr string) error {
	if rel == nil {
		return errors.New("auto-update: missing release metadata")
	}
	// Metadata validation first (platform-independent): the version floor
	// and the signature requirement must hold anywhere this code runs —
	// and must be exercisable by tests on every OS.
	if belowMinTag(rel.TagName) {
		return fmt.Errorf("auto-update: release %s is below the minimum supported version %s — refusing", rel.TagName, MinUpdateTag)
	}
	if !isNewer(version.Version, rel.TagName) {
		return errors.New("auto-update: release is not newer than the running version")
	}
	assetName := updateAssetWin
	var url, sigURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			if url != "" {
				return errors.New("auto-update: duplicate client release asset")
			}
			url = a.URL
		case "manifest.sig":
			if sigURL != "" {
				return errors.New("auto-update: duplicate release manifest")
			}
			sigURL = a.URL
		}
	}
	if url == "" {
		return fmt.Errorf("auto-update: release %s has no %s asset", rel.TagName, assetName)
	}
	if sigURL == "" {
		// Unsigned releases are refused outright: an interceptor who can
		// strip the signature can strip anything else in the feed. The
		// manifest signature binds the TAG to the binary hash, so a
		// forged tag over a real old binary fails verification too
		// (audit round three, N-3).
		return fmt.Errorf("auto-update: release %s has no manifest signature — refusing install", rel.TagName)
	}
	if !validReleaseAssetURL(url, rel.TagName, assetName) || !validReleaseAssetURL(sigURL, rel.TagName, "manifest.sig") {
		return errors.New("auto-update: release asset URL is outside the expected GitHub release")
	}
	// The swap/re-exec machinery is Windows-only.
	if runtime.GOOS != "windows" {
		return errors.New("auto-update: unsupported platform " + runtime.GOOS)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(exe), filepath.Base(exe)+".new-*.exe")
	if err != nil {
		return err
	}
	tmp := temp.Name()
	if err := temp.Close(); err != nil {
		_ = os.Remove(temp.Name())
		return err
	}
	keepStaged := false
	defer func() {
		if !keepStaged {
			_ = os.Remove(tmp)
		}
	}()
	if err := privatefile.Protect(tmp); err != nil {
		return err
	}
	cl := updateClient(socksAddr)
	defer cl.CloseIdleConnections()
	var fresh *protocol.ReleaseManifest
	if requiresFreshManifest(rel.TagName) {
		fresh, err = freshTarget(ctx, cl, rel)
		if err != nil {
			return err
		}
	}

	fetch := func(u string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", transport.BrowserUA)
		return cl.Do(req)
	}

	// Signature first: tiny, and refusing early avoids a wasted download.
	sresp, err := fetch(sigURL)
	if err != nil {
		return err
	}
	if sresp.StatusCode != http.StatusOK {
		_ = sresp.Body.Close()
		return fmt.Errorf("auto-update: manifest download %s", sresp.Status)
	}
	sigRaw, err := io.ReadAll(io.LimitReader(sresp.Body, 4096))
	sresp.Body.Close()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return fmt.Errorf("auto-update: bad signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("auto-update: bad signature length %d", len(sig))
	}
	pub, err := base64.StdEncoding.DecodeString(ReleasePubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("auto-update: embedded release key is corrupt")
	}

	resp, err := fetch(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("auto-update: download %s", resp.Status)
	}
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	// Hard cap enforced DURING the copy: a chunked response (ContentLength
	// -1) used to bypass the old header-only check. Anything beyond the
	// ceiling aborts the install before the swap.
	const maxAsset = 64 << 20
	n, err := io.Copy(io.MultiWriter(out, hasher), io.LimitReader(resp.Body, maxAsset+1))
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if n > maxAsset {
		os.Remove(tmp)
		return fmt.Errorf("auto-update: asset exceeds %d bytes — refusing", maxAsset)
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if fresh != nil && (fresh.Bytes != n || !strings.EqualFold(fresh.SHA256, got)) {
		return errors.New("binary differs from its signed freshness target")
	}
	if want := expectedSHA256(rel.Body); want != "" && got != want {
		os.Remove(tmp)
		return fmt.Errorf("auto-update: sha256 mismatch (got %s)", got[:12])
	}
	// The manifest signature covers "otu-release:<tag>:<asset sha256>":
	// the tag from the (interceptable) feed is cryptographically bound to
	// the binary hash, so neither a forged tag nor a swapped asset can
	// pass — only a tuple the offline release key actually signed.
	if !ed25519.Verify(ed25519.PublicKey(pub), ReleaseMsg(rel.TagName, got), sig) {
		os.Remove(tmp)
		return errors.New("auto-update: release manifest signature verification failed — refusing install")
	}

	// Verify that this signed binary can execute and reports the signed tag
	// before replacing anything. Full post-start readiness remains a release
	// acceptance gate; process creation alone is not a health check.
	pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
	cmd := exec.CommandContext(pctx, tmp, "--version")
	cmd.Env = withoutUpdateEnvironment(os.Environ())
	prepareUpdateHelper(cmd)
	var output boundedUpdateOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	perr := cmd.Run()
	pcancel()
	if perr != nil || output.overflow || strings.TrimSpace(string(output.data)) != "opentunnel client "+rel.TagName {
		return errors.New("auto-update: signed binary failed version preflight")
	}
	if err := armReplacement(ctx, exe, tmp, got); err != nil {
		return err
	}
	keepStaged = true
	log.Printf("auto-update: signed %s transaction armed — awaiting graceful shutdown and replacement readiness", rel.TagName)
	return nil
}

type boundedUpdateOutput struct {
	data     []byte
	overflow bool
}

func (w *boundedUpdateOutput) Write(p []byte) (int, error) {
	n := len(p)
	room := 1024 - len(w.data)
	if len(p) > room {
		w.overflow = true
	}
	w.data = append(w.data, p[:min(room, n)]...)
	return n, nil
}

func validReleaseAssetURL(raw, tag, name string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Path == "/"+updateRepo+"/releases/download/"+tag+"/"+name && u.RawPath == ""
}

// UpdateLoop checks for updates shortly after start and then periodically.
// On success it re-executes the new binary and exits this process.
// socksAddr wires update traffic through the tunnel when direct access to
// github.com is filtered; empty means direct-only.
func UpdateLoop(socksAddr string) {
	RunUpdateLoop(context.Background(), socksAddr, func() { os.Exit(0) })
}

// RunUpdateLoop supports graceful caller shutdown and bounds bulk deferral.
// Even in thin mode metadata is checked; a pending signed update cannot be
// deferred forever merely because the network remains slow.
func RunUpdateLoop(ctx context.Context, socksAddr string, onUpdated func()) {
	var deferredSince time.Time
	if !updateWait(ctx, 30*time.Second) {
		return
	}
	for {
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		rel, err := CheckUpdate(checkCtx, socksAddr)
		cancel()
		if err != nil {
			log.Printf("auto-update: check failed: %v", err)
		} else if rel != nil {
			if ThinMode() {
				if deferredSince.IsZero() {
					deferredSince = time.Now()
				}
				if time.Since(deferredSince) < time.Hour {
					if !updateWait(ctx, 15*time.Minute) {
						return
					}
					continue
				}
			}
			log.Printf("auto-update: %s available (running %s) — downloading", rel.TagName, version.Version)
			dctx, dcancel := context.WithTimeout(ctx, 30*time.Minute)
			err := SelfUpdate(dctx, rel, socksAddr)
			dcancel()
			if err != nil {
				log.Printf("auto-update: %v", err)
			} else {
				if onUpdated != nil {
					onUpdated()
				}
				return
			}
		}
		if !updateWait(ctx, updateCheckGap) {
			return
		}
	}
}

func updateWait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// replaceExecutable never deletes an existing backup. Failed install or
// process creation restores the original path and checks rollback errors.
func replaceExecutable(exe, staged, backup string, start func() error) error {
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		return errors.New("auto-update: backup path already exists")
	}
	if err := os.Rename(exe, backup); err != nil {
		return fmt.Errorf("auto-update: backup: %w", err)
	}
	if err := os.Rename(staged, exe); err != nil {
		return errors.Join(fmt.Errorf("auto-update: install: %w", err), os.Rename(backup, exe))
	}
	if err := start(); err != nil {
		if errors.Is(err, errReplacementStillRunning) {
			// Never swap paths underneath a failed child whose termination
			// could not be confirmed. Keep both files and the recovery journal.
			return fmt.Errorf("auto-update: rollback deferred: %w", err)
		}
		moveErr := os.Rename(exe, staged)
		if moveErr != nil {
			return errors.Join(fmt.Errorf("auto-update: launch failed: %w", err), moveErr)
		}
		return errors.Join(fmt.Errorf("auto-update: launch failed; original restored: %w", err), os.Rename(backup, exe))
	}
	return nil
}
