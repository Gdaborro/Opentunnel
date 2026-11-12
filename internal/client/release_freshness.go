package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

const FreshReleaseFloor = "v1.1.6"

var freshnessMu sync.Mutex

type releaseCheckpoint struct {
	Tag      string `json:"tag"`
	IssuedAt int64  `json:"issued_at"`
}

func requiresFreshManifest(tag string) bool {
	return tag == FreshReleaseFloor || isNewer(FreshReleaseFloor, tag)
}

// Validate freshness even if the feed claims no update is available. Otherwise
// replaying the installed tag bypasses both signature expiry and the checkpoint.
func checkReleaseFreshness(ctx context.Context, cl *http.Client, rel *Release, current string) error {
	if rel == nil {
		return errors.New("release freshness target missing")
	}
	if isNewer(rel.TagName, current) {
		return errors.New("release feed is older than the running version")
	}
	if requiresFreshManifest(rel.TagName) {
		_, err := freshTarget(ctx, cl, rel)
		return err
	}
	if requiresFreshManifest(current) {
		return errors.New("release feed rolled back below the freshness floor")
	}
	freshnessMu.Lock()
	defer freshnessMu.Unlock()
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	previous, err := readReleaseCheckpoint(filepath.Join(store.Dir, "release-checkpoint.json"))
	if err != nil {
		return err
	}
	if previous.Tag != "" {
		return errors.New("release feed rolled back to a legacy target after a signed checkpoint")
	}
	return nil
}

func freshTarget(ctx context.Context, cl *http.Client, rel *Release) (*protocol.ReleaseManifest, error) {
	var manifestURL, sigURL string
	for _, asset := range rel.Assets {
		switch asset.Name {
		case protocol.FreshReleaseName:
			if manifestURL != "" {
				return nil, errors.New("duplicate fresh release metadata")
			}
			manifestURL = asset.URL
		case protocol.FreshReleaseSignature:
			if sigURL != "" {
				return nil, errors.New("duplicate fresh release signature")
			}
			sigURL = asset.URL
		}
	}
	if manifestURL == "" || sigURL == "" {
		return nil, errors.New("new release lacks required signed freshness metadata")
	}
	if !validReleaseAssetURL(manifestURL, rel.TagName, protocol.FreshReleaseName) || !validReleaseAssetURL(sigURL, rel.TagName, protocol.FreshReleaseSignature) {
		return nil, errors.New("fresh release URL escaped its signed target")
	}
	fetch := func(url string, max int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", transport.BrowserUA)
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, errors.New("fresh release metadata unavailable")
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err != nil || int64(len(raw)) > max {
			return nil, errors.New("fresh release metadata oversized or incomplete")
		}
		return raw, nil
	}
	raw, err := fetch(manifestURL, 16<<10)
	if err != nil {
		return nil, err
	}
	sigRaw, err := fetch(sigURL, 1024)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return nil, errors.New("invalid freshness signature encoding")
	}
	pub, err := base64.StdEncoding.DecodeString(ReleasePubKey)
	if err != nil {
		return nil, err
	}
	m, err := protocol.VerifyReleaseManifest(raw, sig, ed25519.PublicKey(pub), time.Now())
	if err != nil {
		return nil, err
	}
	if m.Tag != rel.TagName {
		return nil, errors.New("fresh release tag differs from the selected feed target")
	}
	if err := saveReleaseCheckpoint(m); err != nil {
		return nil, err
	}
	return &m, nil
}

func saveReleaseCheckpoint(m protocol.ReleaseManifest) error {
	freshnessMu.Lock()
	defer freshnessMu.Unlock()
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	path := filepath.Join(store.Dir, "release-checkpoint.json")
	if _, _, _, ok := parseVersion(m.Tag); !ok || !strings.HasPrefix(m.Tag, "v") || m.IssuedAt <= 0 {
		return errors.New("invalid release checkpoint target")
	}
	previous, err := readReleaseCheckpoint(path)
	if err != nil {
		return err
	}
	if previous.Tag != "" && (isNewer(m.Tag, previous.Tag) || m.IssuedAt < previous.IssuedAt) {
		return errors.New("release feed rollback detected")
	}
	raw, err := json.Marshal(releaseCheckpoint{Tag: m.Tag, IssuedAt: m.IssuedAt})
	if err != nil {
		return err
	}
	return privatefile.Write(path, raw)
}

func readReleaseCheckpoint(path string) (releaseCheckpoint, error) {
	var previous releaseCheckpoint
	if raw, err := privatefile.Read(path, 4096); err == nil {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if dec.Decode(&previous) != nil || dec.Decode(&struct{}{}) != io.EOF {
			return previous, errors.New("release checkpoint is corrupt; refusing to reset freshness")
		}
		if _, _, _, ok := parseVersion(previous.Tag); !ok || !strings.HasPrefix(previous.Tag, "v") || previous.IssuedAt <= 0 {
			return previous, errors.New("release checkpoint is corrupt; refusing to reset freshness")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return previous, err
	}
	return previous, nil
}
