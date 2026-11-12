package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/transport"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestUpdateFallbackCoversTLSAndHTTPBlocks(t *testing.T) {
	before := HostileMode()
	setHostileMode(false)
	t.Cleanup(func() { setHostileMode(before) })
	for _, status := range []int{0, 403, 451, 503} {
		calls := 0
		direct := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if status == 0 {
				return nil, errors.New("TLS handshake blocked")
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("blocked")), Header: make(http.Header)}, nil
		})
		via := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("verified later")), Header: make(http.Header)}, nil
		})
		r, _ := http.NewRequest(http.MethodGet, "https://github.com/fixture", nil)
		resp, err := (&updateFallback{direct: direct, via: via}).RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if calls != 1 {
			t.Fatalf("status %d did not fall back", status)
		}
	}
}
func TestUpdateReplacementFailureRestoresOriginal(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "current.exe")
	staged := filepath.Join(dir, "stage.exe")
	backup := filepath.Join(dir, "backup.exe")
	_ = os.WriteFile(exe, []byte("old"), 0o600)
	_ = os.WriteFile(staged, []byte("new"), 0o600)
	if err := replaceExecutable(exe, staged, backup, func() error { return errors.New("synthetic launch failure") }); err == nil {
		t.Fatal("launch failure hidden")
	}
	if raw, _ := os.ReadFile(exe); string(raw) != "old" {
		t.Fatal("old executable not restored")
	}
	_ = os.WriteFile(backup, []byte("user backup"), 0o600)
	if err := replaceExecutable(exe, staged, backup, func() error { return nil }); err == nil {
		t.Fatal("existing backup overwritten")
	}
	if raw, _ := os.ReadFile(backup); string(raw) != "user backup" {
		t.Fatal("backup was discarded")
	}
}
func TestUpdateLoopHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { RunUpdateLoop(ctx, "", nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updater ignored shutdown")
	}
}
func TestCarrierLadderPrecedesQUICAndSSH(t *testing.T) {
	a := NewAdaptive("fixture", transport.WSTLSOptions{}, "auto", time.Second)
	builder := func() transport.Transport { return transport.NewCarrier(transport.CarrierOptions{}) }
	a.EnableCarrier(builder)
	a.EnableH3(builder)
	a.EnableSSHFallback(builder)
	if a.tierCount() != 6 || a.tierName(3) != CarrierTierName || a.tierName(4) != H3TierName || a.sshTierIndex() != 5 {
		t.Fatal("carrier ladder indexes diverged")
	}
}
func TestControlHTTPClientReloadsWithPinsAndConfig(t *testing.T) {
	a := &config.ClientConf{ServerAddr: "one.invalid:443", Fingerprint: strings.Repeat("a", 64)}
	b := &config.ClientConf{ServerAddr: "two.invalid:443", Fingerprint: strings.Repeat("b", 64)}
	first, _, err := panelHTTP(a)
	if err != nil {
		t.Fatal(err)
	}
	second, base, err := panelHTTP(b)
	if err != nil || first == second || !strings.Contains(base, "two.invalid") {
		t.Fatal("control client reused another authority's pin/config")
	}
}
