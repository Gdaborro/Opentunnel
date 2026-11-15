package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"opentunnel/internal/config"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
)

func selectorProfile(t *testing.T, nodes ...serverpool.Node) serverpool.Profile {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 {
		for _, id := range []string{"entry-a", "entry-b", "entry-c"} {
			nodes = append(nodes, serverpool.Node{ID: id, Name: id, Address: id + ".example:443", Pins: []string{strings.Repeat("b", 64)}, WSPath: "/stream"})
		}
	}
	now := time.Now()
	p := serverpool.Profile{Name: "Synthetic pool", AuthorityID: strings.Repeat("a", 64), IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ApprovalRequired: true, Nodes: nodes}
	if err := p.Sign(key, now); err != nil {
		t.Fatal(err)
	}
	return p
}

func invalidatePoolProbe(s *PoolSelector) {
	s.mu.Lock()
	s.probed = time.Now().Add(-2 * poolProbeTTL)
	s.mu.Unlock()
}

func TestPoolSelectorRanksVerifiedLatencyAndAvoidsFlapping(t *testing.T) {
	p := selectorProfile(t)
	s, err := NewPoolSelector(p)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	latency := map[string]time.Duration{"entry-a": 150 * time.Millisecond, "entry-b": 100 * time.Millisecond, "entry-c": 250 * time.Millisecond}
	s.probe = func(_ context.Context, n serverpool.Node) (time.Duration, error) {
		calls.Add(1)
		return latency[n.ID], nil
	}
	if err := s.Refresh(t.Context()); err != nil || s.Current().ID != "entry-b" {
		t.Fatal("not lowest latency", err)
	}
	if err := s.Refresh(t.Context()); err != nil || calls.Load() != 3 {
		t.Fatal("fresh reachability was reprobed")
	}
	p.Nodes[0].Pins[0] = strings.Repeat("f", 64)
	current := s.Current()
	current.Pins[0] = strings.Repeat("f", 64)
	if s.Profile().Nodes[0].Pins[0] != strings.Repeat("b", 64) || s.Current().Pins[0] != strings.Repeat("b", 64) {
		t.Fatal("caller changed accepted trust")
	}
	latency["entry-a"] = 90 * time.Millisecond
	invalidatePoolProbe(s)
	if err := s.Refresh(t.Context()); err != nil || s.Current().ID != "entry-b" {
		t.Fatal("flapped on insignificant improvement", err)
	}
	latency["entry-a"] = 40 * time.Millisecond
	invalidatePoolProbe(s)
	if err := s.Refresh(t.Context()); err != nil || s.Current().ID != "entry-a" {
		t.Fatal("ignored significant improvement", err)
	}
	s.probe = func(context.Context, serverpool.Node) (time.Duration, error) { return 0, errors.New("offline") }
	invalidatePoolProbe(s)
	if err := s.Refresh(t.Context()); err == nil {
		t.Fatal("failed refresh reused stale reachability")
	}
	s.mu.Lock()
	n := len(s.ranks)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("stale nodes retained")
	}
}

func waitPoolWaiters(t *testing.T, s *PoolSelector, n int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		ready := s.refresh != nil && s.refresh.waiters >= n
		s.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refresh waiter did not join")
}

func TestPoolRefreshCoalescesWithoutLeaderCancellation(t *testing.T) {
	s, _ := NewPoolSelector(selectorProfile(t))
	release := make(chan struct{})
	var calls atomic.Int32
	s.probe = func(ctx context.Context, _ serverpool.Node) (time.Duration, error) {
		calls.Add(1)
		select {
		case <-release:
			return time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	leader, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- s.Refresh(leader) }()
	waitPoolWaiters(t, s, 1)
	go func() { second <- s.Refresh(t.Context()) }()
	waitPoolWaiters(t, s, 2)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatal("one waiter canceled another's refresh", err)
	}
	if calls.Load() != 3 {
		t.Fatal("concurrent refresh duplicated probes", calls.Load())
	}
}

func TestPoolRefreshCancelsWhenLastWaiterLeaves(t *testing.T) {
	s, _ := NewPoolSelector(selectorProfile(t))
	stopped := make(chan struct{}, 3)
	s.probe = func(ctx context.Context, _ serverpool.Node) (time.Duration, error) {
		<-ctx.Done()
		stopped <- struct{}{}
		return 0, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- s.Refresh(ctx) }()
	waitPoolWaiters(t, s, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("abandoned refresh retained network work")
	}
}

func TestPoolRefreshNewCallerWaitsForAbandonedJobTeardown(t *testing.T) {
	s, _ := NewPoolSelector(selectorProfile(t))
	release := make(chan struct{})
	var batch atomic.Int32
	s.probe = func(ctx context.Context, _ serverpool.Node) (time.Duration, error) {
		if batch.Load() == 0 {
			<-ctx.Done()
			<-release
			return 0, ctx.Err()
		}
		return time.Millisecond, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { first <- s.Refresh(ctx) }()
	waitPoolWaiters(t, s, 1)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() { second <- s.Refresh(t.Context()) }()
	batch.Store(1)
	close(release)
	select {
	case err := <-second:
		if err != nil {
			t.Fatal("new caller inherited abandoned cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("new caller could not join teardown and refresh")
	}
}

func TestPoolTransportFailoverAndSetupBudget(t *testing.T) {
	s, _ := NewPoolSelector(selectorProfile(t))
	s.probe = func(_ context.Context, n serverpool.Node) (time.Duration, error) {
		return time.Duration(n.ID[len(n.ID)-1]) * time.Millisecond, nil
	}
	if err := s.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	var attempts []string
	var peer net.Conn
	s.dialNode = func(setup, lifetime context.Context, n serverpool.Node, _ time.Duration) (net.Conn, error) {
		attempts = append(attempts, n.ID)
		if _, ok := setup.Deadline(); !ok {
			t.Fatal("unbounded connection setup")
		}
		if lifetime != t.Context() {
			t.Fatal("setup context took ownership of lifetime")
		}
		if n.ID == "entry-a" {
			return nil, errors.New("entry offline")
		}
		c, p := net.Pipe()
		peer = p
		return c, nil
	}
	c, err := s.Transport(time.Second).Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer peer.Close()
	if s.Current().ID != "entry-b" || strings.Join(attempts, ",") != "entry-a,entry-b" {
		t.Fatal("wrong failover", attempts)
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	go func() { _, _ = peer.Write([]byte("alive")) }()
	raw := make([]byte, 5)
	if _, err := io.ReadFull(c, raw); err != nil {
		t.Fatal("stream closed when setup ended", err)
	}
	s.dialNode = func(ctx, _ context.Context, _ serverpool.Node, _ time.Duration) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	if _, err := s.Transport(40 * time.Millisecond).Dial(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("aggregate setup budget not enforced", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("setup budget applied only between nodes")
	}
}

func TestPoolTransportClosesFailedCandidate(t *testing.T) {
	s, _ := NewPoolSelector(selectorProfile(t))
	s.probe = func(context.Context, serverpool.Node) (time.Duration, error) { return time.Millisecond, nil }
	_ = s.Refresh(t.Context())
	var peers []net.Conn
	s.dialNode = func(context.Context, context.Context, serverpool.Node, time.Duration) (net.Conn, error) {
		c, p := net.Pipe()
		peers = append(peers, p)
		return c, errors.New("partial setup")
	}
	if _, err := s.Transport(time.Second).Dial(t.Context()); err == nil {
		t.Fatal("partial connection accepted")
	}
	for _, peer := range peers {
		defer peer.Close()
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
			t.Fatal("failed candidate leaked", err)
		}
	}
}

func poolHTTPFixture(t *testing.T, login bool, handler func(http.ResponseWriter, *http.Request)) (serverpool.Profile, *httptest.Server) {
	t.Helper()
	var info serverpool.Info
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == serverpool.InfoPath {
			if r.Header.Get("X-Otu-Proof") != "" {
				t.Error("credentials in capability probe")
			}
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	n := serverpool.Node{ID: "local-entry", Name: "Synthetic entry", Address: "entry.example:8443", DialAddress: srv.Listener.Addr().String(), Pins: []string{hex.EncodeToString(transport.FingerprintCert(srv.Certificate().Raw))}, WSPath: "/stream"}
	p := selectorProfile(t, n)
	if login {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		p.LoginRequired = true
		_ = p.Sign(key, time.Now())
	}
	info = serverpool.Info{Version: 1, PoolID: p.ID, AuthorityID: p.AuthorityID, LoginRequired: p.LoginRequired, ApprovalRequired: true}
	return p, srv
}

func poolDeviceConfig(t *testing.T, p serverpool.Profile) (*config.ClientConf, *DeviceIdentity) {
	t.Helper()
	ts, err := NewPoolTokenStore(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	device, err := ts.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	n := p.Nodes[0]
	return &config.ClientConf{Pool: &p, PoolNode: func() serverpool.Node { return n }}, device
}

func TestPoolEnrollmentNoRedirectOrCrossOperatorIdentity(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	var redirectCalls atomic.Int32
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirectCalls.Add(1) }))
	defer redirect.Close()
	var requestCalls atomic.Int32
	var seenPassword atomic.Value
	p, _ := poolHTTPFixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		requestCalls.Add(1)
		var data map[string]string
		_ = json.NewDecoder(r.Body).Decode(&data)
		seenPassword.Store(data["password"])
		http.Redirect(w, r, redirect.URL+"/steal", http.StatusTemporaryRedirect)
	})
	cfg, device := poolDeviceConfig(t, p)
	password := []byte("Synthetic-password-not-persisted")
	if err := EnrollPool(t.Context(), cfg, device, &EnrollmentCredentials{Username: "synthetic-user", Password: password}); err == nil {
		t.Fatal("redirect accepted")
	}
	if redirectCalls.Load() != 0 || requestCalls.Load() != 1 || seenPassword.Load() != string(password) {
		t.Fatal("password redirected or retried")
	}
	root, _ := NewTokenStore()
	defaultIdentity := &DeviceIdentity{Token: "synthetic-default-token-123456", Fingerprint: "default-fixture", DeviceName: "default"}
	raw, _ := json.Marshal(defaultIdentity)
	if err := os.WriteFile(root.TokenPath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := EnrollPool(t.Context(), cfg, defaultIdentity, nil); err == nil {
		t.Fatal("default device identity sent to another operator")
	}
	if _, _, _, _, err := TokenStatus(cfg, defaultIdentity.Token); err == nil {
		t.Fatal("default token used for imported-pool status")
	}
	if requestCalls.Load() != 1 {
		t.Fatal("foreign identity reached enrollment endpoint")
	}
	_ = filepath.WalkDir(root.Dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			raw, _ := os.ReadFile(path)
			if bytes.Contains(raw, password) {
				t.Error("password persisted in", filepath.Base(path))
			}
		}
		return err
	})
}

func TestPoolCapabilityMismatchAndCallbackCannotRedirectCredentials(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	var calls atomic.Int32
	p, srv := poolHTTPFixture(t, true, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"status":"pending"}`)
	})
	cfg, device := poolDeviceConfig(t, p)
	bad := p.Nodes[0]
	bad.DialAddress = "127.0.0.1:1"
	cfg.PoolNode = func() serverpool.Node { return bad }
	if err := EnrollPool(t.Context(), cfg, device, &EnrollmentCredentials{Username: "synthetic-user", Password: []byte("Synthetic-password")}); err == nil {
		t.Fatal("callback substituted an unaccepted node")
	}
	if _, _, err := panelHTTP(cfg); err == nil {
		t.Fatal("control callback redirected operator identity")
	}
	cfg.PoolNode = func() serverpool.Node { return p.Nodes[0] }
	original := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == serverpool.InfoPath {
			_ = json.NewEncoder(w).Encode(serverpool.Info{Version: 1, PoolID: p.ID, AuthorityID: strings.Repeat("f", 64), LoginRequired: true, ApprovalRequired: true})
			return
		}
		original.ServeHTTP(w, r)
	})
	if err := EnrollPool(t.Context(), cfg, device, &EnrollmentCredentials{Username: "synthetic-user", Password: []byte("Synthetic-password")}); err == nil {
		t.Fatal("independent authority requested password")
	}
	if calls.Load() != 0 {
		t.Fatal("credentials sent before verifying matching authority")
	}
}

func TestPoolWSTLSUsesTrustedAuthorityAndKeepsStreamAfterSetup(t *testing.T) {
	var upgrade atomic.Int32
	p, _ := poolHTTPFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "entry.example:8443" || r.Header.Get("Origin") != "https://entry.example:8443" {
			t.Error("HTTP authority inherited TCP port", r.Host, r.Header.Get("Origin"))
			http.Error(w, "wrong authority", 400)
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		upgrade.Add(1)
		c := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		_, _ = io.Copy(c, c)
	})
	s, _ := NewPoolSelector(p)
	setup, cancel := context.WithTimeout(t.Context(), time.Second)
	c, err := s.Transport(time.Second).(transport.SetupDialer).DialSetup(setup, t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("alive-after-setup")); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, len("alive-after-setup"))
	if _, err := io.ReadFull(c, raw); err != nil || string(raw) != "alive-after-setup" {
		t.Fatal("setup cancellation closed stream", err)
	}
	if upgrade.Load() != 1 {
		t.Fatal("wrong number of transport attempts")
	}
}

func TestPoolTransportDoesNotUseUnacceptedLegacyPath(t *testing.T) {
	var legacy atomic.Int32
	p, _ := poolHTTPFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.LegacyWSPath {
			legacy.Add(1)
		}
		http.NotFound(w, r)
	})
	s, _ := NewPoolSelector(p)
	if c, err := s.Transport(time.Second).Dial(t.Context()); err == nil {
		c.Close()
		t.Fatal("missing signed websocket path unexpectedly connected")
	}
	if legacy.Load() != 0 {
		t.Fatal("signed pool dialed an unaccepted legacy websocket path")
	}
}

func TestPoolInnerTLSFailureUsesSetupBudget(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	p, _ := poolHTTPFixture(t, false, func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		c := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		_, _ = io.Copy(io.Discard, c) // accepts the outer stream but never confirms inner TLS
	})
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	p.Nodes[0].InnerTLSPins = []string{strings.Repeat("a", 64)}
	if err := p.Sign(key, time.Now()); err != nil {
		t.Fatal(err)
	}
	s, _ := NewPoolSelector(p)
	s.probe = func(context.Context, serverpool.Node) (time.Duration, error) { return time.Millisecond, nil }
	start := time.Now()
	if c, err := s.Transport(60 * time.Millisecond).Dial(t.Context()); err == nil {
		c.Close()
		t.Fatal("unconfirmed inner TLS connection accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("inner TLS or graceful close exceeded pool setup budget")
	}
}

func TestPoolProfileExpiryBlocksWarmAdaptiveRequests(t *testing.T) {
	p := selectorProfile(t)
	s, _ := NewPoolSelector(p)
	a := NewAdaptive("", transport.WSTLSOptions{}, "fast", time.Second)
	a.UseTrustedPool(s)
	defer a.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	expired := s.Profile()
	expired.ExpiresAt = time.Now().Add(-time.Second).Unix()
	expired.IssuedAt = expired.ExpiresAt - 60
	if err := expired.Sign(key, time.Unix(expired.IssuedAt, 0)); err != nil {
		t.Fatal(err)
	}
	s.profile = expired
	called := false
	if _, err := adaptiveAttempt(a, t.Context(), func(*Client) (bool, error) { called = true; return true, nil }); err == nil || called {
		t.Fatal("warm adaptive path ignored profile expiry")
	}
}

func TestPoolIdentityAndControlStateAreOperatorScoped(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	p1, p2 := selectorProfile(t), selectorProfile(t)
	s1, _ := NewPoolTokenStore(p1.ID)
	s2, _ := NewPoolTokenStore(p2.ID)
	d1, err := s1.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s2.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := s1.EnsureSSHKey()
	k2, _ := s2.EnsureSSHKey()
	if d1.Token == d2.Token || d1.Fingerprint == d2.Fingerprint || k1 == k2 {
		t.Fatal("operators shared device identity")
	}
	s1.MarkApproved(d1.Fingerprint)
	s1.WriteHardBan("synthetic scoped ban", "permanent")
	if s2.EverApproved(d1.Fingerprint) || s2.IsHardBanned() {
		t.Fatal("approval/ban crossed operators")
	}
	s2.ClearBan()
	if !s1.IsHardBanned() {
		t.Fatal("another pool cleared a ban")
	}
	SetPoolControlChannel(p1.ID, func(context.Context, protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
		return &protocol.CtrlResponse{OK: true}, nil
	})
	defer SetControlChannel(nil)
	if currentPoolCtrl(p1.ID) == nil || currentPoolCtrl(p2.ID) != nil || currentCtrl() != nil {
		t.Fatal("control channel used another operator's session")
	}
}

func TestPoolClientNeverUsesLegacyMasterOrUnsignedDowngrade(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	p := selectorProfile(t)
	ts, _ := NewPoolTokenStore(p.ID)
	df, err := ts.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	var sawLegacy atomic.Bool
	finished := make(chan struct{})
	tr := &pipeTransport{serverFn: func(c net.Conn) {
		defer c.Close()
		defer close(finished)
		hs, err := protocol.ReadHandshake(c)
		if err != nil {
			return
		}
		if hs.Version != protocol.ProtoVersion || hs.Token != df.Token {
			t.Error("used legacy/default identity")
		}
		_, _ = c.Write([]byte{protocol.ProtoVersionLegacy, protocol.StatusBadVersion})
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		raw := make([]byte, 1)
		if n, _ := c.Read(raw); n > 0 {
			sawLegacy.Store(true)
		}
	}}
	cl := NewWithOptions(tr, Options{IdentityScope: p.ID, Token: "legacy-master-must-not-send"})
	if candidates := cl.authCandidates(); len(candidates) != 1 || candidates[0] != df.Token {
		t.Fatal("master token in pool auth candidates")
	}
	if c, _, _, err := cl.dialAuthenticated(t.Context(), time.Second); err == nil {
		c.Close()
		t.Fatal("accepted legacy server for trusted pool")
	}
	<-finished
	if sawLegacy.Load() {
		t.Fatal("retried unsigned handshake")
	}
	if err := os.WriteFile(ts.SSHPrivatePath(), []byte("corrupt private key"), 0600); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	cl.Transport = &countingPoolTransport{dials: &dials}
	if _, _, _, err := cl.dialAuthenticated(t.Context(), time.Second); err == nil || dials.Load() != 0 {
		t.Fatal("sent token before usable scoped key")
	}
}

type countingPoolTransport struct{ dials *atomic.Int32 }

func (*countingPoolTransport) Name() string { return "test" }
func (t *countingPoolTransport) Dial(context.Context) (net.Conn, error) {
	t.dials.Add(1)
	return nil, errors.New("must not dial")
}
