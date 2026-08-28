package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

func newServerHandler(token string) http.Handler {
	return server.Handler(server.Options{Token: token, AllowRestrictedTargets: true})
}

type failTransport struct{ calls *int }

func (f *failTransport) Name() string { return "fake-fast-fail" }
func (f *failTransport) Dial(ctx context.Context) (net.Conn, error) {
	*f.calls++
	return nil, errors.New("simulated: fast transport blocked")
}

const adaptiveToken = "adaptive-test-token"

// startAdaptiveFixture runs a local server + target and returns an Adaptive.
// failFast makes only the "fast" slot fail; failAll makes every slot fail.
func startAdaptiveFixture(t *testing.T, profile string, fastCalls *int, failAll bool) (*Adaptive, *protocol.Address, transport.WSTLSOptions, func()) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	}))
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, fp, err := transport.LoadOrCreateCert(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srvHTTP := &http.Server{
		Handler:   newServerHandler(adaptiveToken),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}},
	}
	go func() { _ = srvHTTP.ServeTLS(srvLn, "", "") }()

	base := transport.WSTLSOptions{
		ServerAddr:  srvLn.Addr().String(),
		Fingerprint: fp,
	}
	a := NewAdaptive(adaptiveToken, base, profile, 5*time.Second)
	realFactory := defaultFactory
	a.factory = func(a *Adaptive, idx int) *Client {
		// Fail fast always; when failAll, also fail every ws-tls tier.
		if idx == 0 || (failAll && idx < len(profileOrder)) {
			return NewWithOptions(&failTransport{calls: fastCalls}, Options{Token: adaptiveToken})
		}
		return realFactory(a, idx)
	}
	host, portStr, _ := net.SplitHostPort(target.Listener.Addr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	addr, err := protocol.ParseAddress(host, port)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		target.Close()
		srvHTTP.Close()
	}
	return a, addr, base, cleanup
}

func TestAdaptiveEscalatesAndSticks(t *testing.T) {
	calls := 0
	a, addr, _, cleanup := startAdaptiveFixture(t, "auto", &calls, false)
	defer cleanup()

	conn, err := a.DialTunnel(context.Background(), addr)
	if err != nil {
		t.Fatalf("expected success after escalation: %v", err)
	}
	conn.Close()
	if a.idx != 1 {
		t.Fatalf("expected sticky escalation to balanced (idx=1), got %d", a.idx)
	}

	// Second dial should go straight to balanced — fast is not retried.
	conn2, err := a.DialTunnel(context.Background(), addr)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	conn2.Close()
	if calls != 1 {
		t.Fatalf("fast profile should not be retried after escalation, calls=%d", calls)
	}
}

func TestFixedProfileNeverEscalates(t *testing.T) {
	calls := 0
	a, addr, _, cleanup := startAdaptiveFixture(t, "stealth", &calls, true)
	defer cleanup()

	if _, err := a.DialTunnel(context.Background(), addr); err == nil {
		t.Fatal("expected failure when every profile fails")
	}
	if a.Current() != ProfileStealth || a.idx != 2 {
		t.Fatalf("fixed profile must not escalate, idx=%d", a.idx)
	}
	if calls != 1 { // fixed profile => exactly one attempt at idx 2
		t.Fatalf("fixed profile must attempt once, calls=%d", calls)
	}
}

// TestSSHFallbackTierRescuesTotalTLSInterception: all ws-tls tiers fail
// (simulating a full MITM), the ssh last-resort tier succeeds and sticks.
func TestSSHFallbackTierRescuesTotalTLSInterception(t *testing.T) {
	wstlsCalls := 0
	a, addr, base, cleanup := startAdaptiveFixture(t, "auto", &wstlsCalls, true)
	defer cleanup()

	// A genuinely working transport for the ssh tier (ws stands in for ssh
	// at unit level — the tier mechanics are what we're testing).
	realTr := transport.NewWSTLS(base)
	a.EnableSSHFallback(func() transport.Transport { return realTr })

	conn, err := a.DialTunnel(context.Background(), addr)
	if err != nil {
		t.Fatalf("ssh tier should rescue total tls interception: %v", err)
	}
	conn.Close()
	if a.Current() != SshTierName || a.idx != 3 {
		t.Fatalf("expected sticky escalation to ssh tier (idx=3), got idx=%d", a.idx)
	}
}
