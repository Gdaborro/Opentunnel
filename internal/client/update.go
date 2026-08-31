package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

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
func LatestRelease(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://api.github.com/repos/"+updateRepo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "otu-client/"+version.Version)
	resp, err := http.DefaultClient.Do(req)
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
func CheckUpdate(ctx context.Context) (*Release, error) {
	rel, err := LatestRelease(ctx)
	if err != nil {
		return nil, err
	}
	if !isNewer(version.Version, rel.TagName) {
		return nil, nil
	}
	return rel, nil
}

// SelfUpdate downloads the release asset for this platform, verifies it,
// swaps the running binary, and re-executes. Returns after spawning the
// new process; the caller should exit.
func SelfUpdate(ctx context.Context, rel *Release) error {
	assetName := updateAssetWin
	if runtime.GOOS != "windows" {
		return errors.New("auto-update: unsupported platform " + runtime.GOOS)
	}
	var url string
	for _, a := range rel.Assets {
		if a.Name == assetName {
			url = a.URL
			break
		}
	}
	if url == "" {
		return fmt.Errorf("auto-update: release %s has no %s asset", rel.TagName, assetName)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tmp := exe + ".new"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "otu-client/"+version.Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("auto-update: download %s", resp.Status)
	}
	// Refuse absurd downloads even if a release asset were misconfigured:
	// the client is ~11 MB, so 64 MB is a generous ceiling.
	if resp.ContentLength > 64<<20 {
		return fmt.Errorf("auto-update: asset too large (%d bytes)", resp.ContentLength)
	}
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, hasher), resp.Body); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
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
	log.Printf("auto-update: updated to %s — restarting", rel.TagName)
	return nil
}

// UpdateLoop checks for updates shortly after start and then periodically.
// On success it re-executes the new binary and exits this process.
func UpdateLoop() {
	for {
		time.Sleep(30 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		rel, err := CheckUpdate(ctx)
		cancel()
		if err != nil {
			log.Printf("auto-update: check failed: %v", err)
		} else if rel != nil {
			log.Printf("auto-update: %s available (running %s) — downloading", rel.TagName, version.Version)
			dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Minute)
			err := SelfUpdate(dctx, rel)
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
