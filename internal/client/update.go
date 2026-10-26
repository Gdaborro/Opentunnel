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
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

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
	resp, err := updateClient(socksAddr).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("github: %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

var verRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// parseVersion extracts major/minor/patch from a tag like "v0.9.1".
func parseVersion(s string) (major, minor, patch int, ok bool) {
	m := verRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
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
				return sum
			}
		}
	}
	return ""
}

// CheckUpdate returns the release to install, or nil when up to date.
func CheckUpdate(ctx context.Context, socksAddr string) (*Release, error) {
	rel, err := LatestRelease(ctx, socksAddr)
	if err != nil {
		return nil, err
	}
	if !isNewer(version.Version, rel.TagName) {
		return nil, nil
	}
	return rel, nil
}

// updateClient builds an HTTP client for update traffic: direct connection
// first (fast path), falling back to the tunnel's SOCKS proxy when direct
// is blocked (school/corporate firewalls that filter github.com). TLS stays
// end-to-end in both cases, so the fallback changes only the TCP path —
// integrity still rests on the SHA-256 check in SelfUpdate.
func updateClient(socksAddr string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dd := &net.Dialer{Timeout: 8 * time.Second}
				if conn, err := dd.DialContext(ctx, network, addr); err == nil {
					return conn, nil
				} else if socksAddr == "" {
					return nil, err
				}
				return socksDialContext(ctx, socksAddr, network, addr)
			},
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}
}

// socksDialContext dials through a SOCKS5 proxy with ctx awareness.
func socksDialContext(ctx context.Context, socksAddr, network, addr string) (net.Conn, error) {
	sd, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := sd.Dial(network, addr)
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		// Don't leak the late conn: close it if it lands after cancel.
		go func() {
			if r := <-ch; r.err == nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// SelfUpdate downloads the release asset for this platform, verifies it
// (Ed25519 signature against the baked-in release key, then the sha256
// line from the notes), swaps the running binary, and re-executes. The
// signature is the trust anchor: release metadata, download URL and the
// sha256 line all ride channels a middlebox can rewrite, but a forged
// binary cannot produce a valid signature for the offline private key.
func SelfUpdate(ctx context.Context, rel *Release, socksAddr string) error {
	assetName := updateAssetWin
	if runtime.GOOS != "windows" {
		return errors.New("auto-update: unsupported platform " + runtime.GOOS)
	}
	var url, sigURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case assetName:
			url = a.URL
		case assetName + ".sig":
			sigURL = a.URL
		}
	}
	if url == "" {
		return fmt.Errorf("auto-update: release %s has no %s asset", rel.TagName, assetName)
	}
	if sigURL == "" {
		// Unsigned releases are refused outright: an interceptor who can
		// strip the signature can strip anything else in the feed.
		return fmt.Errorf("auto-update: release %s is unsigned — refusing install", rel.TagName)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tmp := exe + ".new"

	fetch := func(u string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", transport.BrowserUA)
		return updateClient(socksAddr).Do(req)
	}

	// Signature first: tiny, and refusing early avoids a wasted download.
	sresp, err := fetch(sigURL)
	if err != nil {
		return err
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
	if want := expectedSHA256(rel.Body); want != "" {
		if got := hex.EncodeToString(hasher.Sum(nil)); got != want {
			os.Remove(tmp)
			return fmt.Errorf("auto-update: sha256 mismatch (got %s)", got[:12])
		}
	} else {
		os.Remove(tmp)
		return errors.New("auto-update: release notes missing sha256 — refusing install")
	}
	// The signature covers the downloaded file bytes.
	fileData, err := os.ReadFile(tmp)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), fileData, sig) {
		os.Remove(tmp)
		return errors.New("auto-update: release signature verification failed — refusing install")
	}

	// Windows allows renaming a running exe: current -> .old, new -> current.
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("auto-update: rename current: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		// Roll back so the device is never left without a binary.
		_ = os.Rename(old, exe)
		return fmt.Errorf("auto-update: install: %w", err)
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Dir = ""
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("auto-update: re-exec failed (new binary in place): %w", err)
	}
	log.Printf("auto-update: updated to %s (signature verified) — restarting", rel.TagName)
	return nil
}

// UpdateLoop checks for updates shortly after start and then periodically.
// On success it re-executes the new binary and exits this process.
// socksAddr wires update traffic through the tunnel when direct access to
// github.com is filtered; empty means direct-only.
func UpdateLoop(socksAddr string) {
	for {
		if ThinMode() {
			// Shaped uplink: update payloads are bulk — stand down and
			// retry later instead of fighting interactive traffic.
			time.Sleep(15 * time.Minute)
			continue
		}
		time.Sleep(30 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		rel, err := CheckUpdate(ctx, socksAddr)
		cancel()
		if err != nil {
			log.Printf("auto-update: check failed: %v", err)
		} else if rel != nil {
			log.Printf("auto-update: %s available (running %s) — downloading", rel.TagName, version.Version)
			dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Minute)
			err := SelfUpdate(dctx, rel, socksAddr)
			dcancel()
			if err != nil {
				log.Printf("auto-update: %v", err)
			} else {
				os.Exit(0)
			}
		}
		time.Sleep(updateCheckGap)
	}
}
