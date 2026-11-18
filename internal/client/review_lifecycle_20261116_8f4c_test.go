//go:build netenvfixture

package client

// Internal, sanitized review reproductions. These assert the desired behavior
// and deliberately fail on the reviewed candidate. No installed state is read;
// identities, certificates, settings and sockets are temporary or loopback-only.

import (
	"bytes"
	"context"
	"crypto/tls"
	"debug/buildinfo"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/xtaci/smux"
	"opentunnel/internal/config"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

const review8f4cToken = "sanitized-review-fixture-token-20261116"

type review8f4cTransport struct {
	dial func(context.Context) (net.Conn, error)
}

func (*review8f4cTransport) Name() string { return "ws-tls" }
func (t *review8f4cTransport) Dial(ctx context.Context) (net.Conn, error) {
	return t.dial(ctx)
}

func review8f4cIdentity(t *testing.T) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	store, err := NewTokenStore()
	if err != nil {
		t.Fatal(err)
	}
	// Seed instead of creating a machine-derived device identity.
	raw := []byte(`{"token":"` + review8f4cToken + `","fingerprint":"sanitized-review-fixture","device_name":"sanitized-fixture"}`)
	if err := privatefile.WriteNew(store.TokenPath(), raw); err != nil {
		t.Fatal(err)
	}
}

func review8f4cWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sanitized fixture did not finish teardown")
	}
}

func TestReview8f4cDrainCancelsUnfinishedMuxSetup(t *testing.T) {
	started := make(chan struct{})
	done := make(chan struct{})
	p := newMuxPool(func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}, 1, 3*time.Second)
	t.Cleanup(func() { _ = p.Close(); review8f4cWait(t, done) })
	go func() { defer close(done); _, _ = p.Open(t.Context()) }()
	<-started
	p.Drain()
	select {
	case <-done:
	case <-time.After(120 * time.Millisecond):
		t.Error("drain retained an unfinished dial although there is no active transfer")
	}
}

func TestReview8f4cCloseOwnsRawAuthenticationInProgress(t *testing.T) {
	review8f4cIdentity(t)
	left, right := net.Pipe()
	ready := make(chan struct{})
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		if _, err := protocol.ReadHandshake(right); err == nil {
			close(ready)
			_, _ = io.Copy(io.Discard, right) // deliberately never send the verdict
		}
	}()
	cl := NewWithOptions(&review8f4cTransport{dial: func(context.Context) (net.Conn, error) { return left, nil }}, Options{Token: review8f4cToken, DialTimeout: 3 * time.Second})
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
		_ = cl.Close()
		review8f4cWait(t, done)
		review8f4cWait(t, peerDone)
	})
	go func() { defer close(done); _, _ = cl.ProbeSession(t.Context()) }()
	select {
	case <-ready:
	case <-done:
		t.Fatal("fixture did not reach authentication")
	case <-time.After(2 * time.Second):
		t.Fatal("fixture authentication startup timed out")
	}
	_ = cl.Close()
	select {
	case <-done:
	case <-time.After(120 * time.Millisecond):
		t.Error("Client.Close returned but unadopted raw authentication IO is still blocked")
	}
}

func TestReview8f4cNonMuxUsesOneSetupBudget(t *testing.T) {
	review8f4cIdentity(t)
	left, right := net.Pipe()
	peerDone := make(chan struct{})
	const budget = 200 * time.Millisecond
	const phaseDelay = 140 * time.Millisecond
	go func() {
		defer close(peerDone)
		defer right.Close()
		hs, err := protocol.ReadHandshake(right)
		if err != nil {
			return
		}
		time.Sleep(phaseDelay)
		if err := protocol.WriteHandshakeStatus(right, hs.Version, protocol.StatusOK); err != nil {
			return
		}
		salt := hs.Salt
		if salt == nil {
			salt, err = protocol.ReadSalt(right)
			if err != nil {
				return
			}
		}
		sec, err := protocol.ServerSideSecureStream(right, hs.Token, salt)
		if err != nil {
			return
		}
		if _, err := protocol.ReadToken(sec); err != nil {
			return
		}
		time.Sleep(phaseDelay)
		if err := protocol.WriteToken(sec, "ok"); err != nil {
			return
		}
		if _, err := protocol.ReadTarget(sec); err != nil {
			return
		}
		time.Sleep(phaseDelay)
		_ = protocol.WriteTargetResponse(sec, hs.Version, protocol.StatusOK)
	}()
	cl := NewWithOptions(&review8f4cTransport{dial: func(context.Context) (net.Conn, error) { return left, nil }}, Options{Token: review8f4cToken, DialTimeout: budget})
	t.Cleanup(func() { _ = left.Close(); _ = right.Close(); _ = cl.Close(); review8f4cWait(t, peerDone) })
	addr, _ := protocol.ParseAddress("127.0.0.1", 1)
	start := time.Now()
	c, err := cl.DialTunnel(t.Context(), addr)
	if c != nil {
		_ = c.Close()
	}
	if err == nil {
		t.Errorf("setup succeeded after %s despite the %s handshake+target budget", time.Since(start).Round(time.Millisecond), budget)
	}
}

func TestReview8f4cWarmMuxTargetHonorsCallerCancellation(t *testing.T) {
	left, right := net.Pipe()
	peer, err := smux.Server(right, muxConfig())
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	release := make(chan struct{})
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		stream, err := peer.AcceptStream()
		if err != nil {
			return
		}
		if _, err := protocol.ReadTarget(stream); err == nil {
			close(ready)
			<-release // no target response before cancellation
		}
	}()
	cl := NewWithOptions(&review8f4cTransport{}, Options{Mux: true, DialTimeout: 3 * time.Second})
	cl.poolOnce.Do(func() {
		cl.pool = newMuxPool(func(context.Context) (net.Conn, error) { return left, nil }, 1, time.Second)
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		close(release)
		_ = cl.Close()
		_ = peer.Close()
		review8f4cWait(t, done)
		review8f4cWait(t, peerDone)
	})
	addr, _ := protocol.ParseAddress("127.0.0.1", 1)
	go func() { defer close(done); _, _ = cl.DialTunnel(ctx, addr) }()
	select {
	case <-ready:
	case <-done:
		t.Fatal("fixture did not reach target setup")
	case <-time.After(2 * time.Second):
		t.Fatal("fixture target setup timed out")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(120 * time.Millisecond):
		t.Error("cancelled target setup on a warm mux session is still waiting on the independent IO deadline")
	}
}

func TestReview8f4cDNSRotationRetriesHealthyWSOnlyEntry(t *testing.T) {
	a := NewAdaptive("", transport.WSTLSOptions{}, "auto", time.Second)
	a.SetEntries([]transport.WSTLSOptions{{ServerAddr: "dead-fixture.invalid:443"}, {ServerAddr: "healthy-fixture.invalid:443"}})
	a.factory = func(*Adaptive, int) *Client { return NewWithOptions(&review8f4cTransport{}, Options{}) }
	t.Cleanup(func() { _ = a.Close(); setHostileMode(false) })
	_, err := adaptiveAttempt(a, t.Context(), func(*Client) (bool, error) {
		return false, &net.DNSError{Err: "no such host", Name: "dead-fixture.invalid", IsNotFound: true}
	})
	if err == nil || a.base.ServerAddr != "healthy-fixture.invalid:443" {
		t.Fatal("fixture did not rotate its failed entry")
	}
	attempts := 0
	_, err = adaptiveAttempt(a, t.Context(), func(*Client) (bool, error) { attempts++; return true, nil })
	if err != nil || attempts == 0 {
		t.Errorf("healthy rotated WS-only entry was never attempted: attempts=%d err=%v", attempts, err)
	}
}

func TestReview8f4cNetworkChangeRejectsOldAttemptVerdict(t *testing.T) {
	a := NewAdaptive("", transport.WSTLSOptions{}, "auto", time.Second)
	a.factory = func(*Adaptive, int) *Client { return NewWithOptions(&review8f4cTransport{}, Options{}) }
	t.Cleanup(func() { _ = a.Close(); setHostileMode(false) })
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = adaptiveAttempt(a, t.Context(), func(*Client) (bool, error) {
			close(started)
			<-release
			return false, errors.New("transport: server certificate fingerprint mismatch")
		})
	}()
	<-started
	a.NetworkChanged()
	close(release)
	review8f4cWait(t, done)
	a.mu.Lock()
	hostile := a.hostile
	a.mu.Unlock()
	if hostile {
		t.Error("a completed attempt from the old network re-latched hostile mode after NetworkChanged reset it")
	}
}

func TestReview8f4cNetworkChangeInvalidatesInProgressPoolRefresh(t *testing.T) {
	s, err := NewPoolSelector(selectorProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.probe = func(context.Context, serverpool.Node) (time.Duration, error) {
		once.Do(func() { close(started) })
		<-release
		return time.Millisecond, nil
	}
	a := NewAdaptive("", transport.WSTLSOptions{}, "auto", time.Second)
	a.UseTrustedPool(s)
	defer a.Close()
	go func() { defer close(done); _ = s.Refresh(t.Context()) }()
	<-started
	a.NetworkChanged()
	close(release)
	review8f4cWait(t, done)
	s.mu.Lock()
	reused := len(s.ranks) > 0 && !s.probed.IsZero()
	s.mu.Unlock()
	if reused {
		t.Error("a pool probe job from before NetworkChanged published ranks as fresh for the new network")
	}
}

func TestReview8f4cRuntimeStatusReportsRotatedEntry(t *testing.T) {
	review8f4cIdentity(t)
	cfg := &config.ClientConf{ServerAddr: "original-fixture.invalid:443"}
	a := NewAdaptive("", transport.WSTLSOptions{}, "auto", time.Second)
	a.SetEntries([]transport.WSTLSOptions{{ServerAddr: cfg.ServerAddr}, {ServerAddr: "rotated-fixture.invalid:443"}})
	defer a.Close()
	if !a.RotateEntry("sanitized-status-fixture") {
		t.Fatal("fixture did not rotate")
	}
	if err := SaveRuntimeStatus(cfg, a, "", nil, false, true); err != nil {
		t.Fatal(err)
	}
	s, err := ReadRuntimeStatus()
	if err != nil {
		t.Fatal(err)
	}
	if s.Node != a.base.ServerAddr {
		t.Errorf("status identifies the startup entry instead of the active entry: node=%s active=%s", s.Node, a.base.ServerAddr)
	}
}

func TestReview8f4cH3ShutdownCancelsDNS(t *testing.T) {
	// Replace only the in-process resolver. Ignore the OS-supplied DNS address;
	// every DNS socket is connected to this intentionally silent loopback port.
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	before := net.DefaultResolver
	var stopped atomic.Bool
	var mu sync.Mutex
	var sockets []net.Conn
	started := make(chan struct{}, 8)
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if stopped.Load() {
			return nil, errors.New("sanitized DNS fixture stopped")
		}
		c, err := (&net.Dialer{}).DialContext(ctx, "udp4", dns.LocalAddr().String())
		if err != nil {
			return nil, err
		}
		mu.Lock()
		if stopped.Load() {
			mu.Unlock()
			_ = c.Close()
			return nil, errors.New("sanitized DNS fixture stopped")
		}
		sockets = append(sockets, c)
		mu.Unlock()
		select {
		case started <- struct{}{}:
		default:
		}
		return c, nil
	}}
	tr := transport.NewH3(transport.H3Options{ServerAddr: "sanitized-review-dns.invalid:443", Insecure: true, DialTimeout: time.Second})
	done := make(chan struct{})
	var closeOnce sync.Once
	startClose := func() {
		closeOnce.Do(func() { go func() { _ = tr.(interface{ Close() error }).Close(); close(done) }() })
	}
	t.Cleanup(func() {
		stopped.Store(true)
		mu.Lock()
		for _, c := range sockets {
			_ = c.Close()
		}
		mu.Unlock()
		startClose()
		review8f4cWait(t, done)
		net.DefaultResolver = before
		_ = dns.Close()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if c, err := tr.Dial(ctx); c != nil || !errors.Is(err, context.DeadlineExceeded) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("fixture did not cancel during DNS: %v", err)
	}
	select {
	case <-started:
	default:
		t.Fatal("loopback DNS fixture was not used")
	}
	startClose()
	select {
	case <-done:
	case <-time.After(120 * time.Millisecond):
		t.Error("H3.Close is waiting for DNS launched without the cancelled setup context")
	}
}

func TestReview8f4cH3ReadAndWriteDeadlinesAreIndependent(t *testing.T) {
	dir := t.TempDir()
	cert, fp, err := transport.LoadOrCreateCert(filepath.Join(dir, "fixture-cert.pem"), filepath.Join(dir, "fixture-key.pem"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	})}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close(); _ = pc.Close(); review8f4cWait(t, serverDone) })
	tr := transport.NewH3(transport.H3Options{ServerAddr: pc.LocalAddr().String(), Fingerprint: fp, DialTimeout: time.Second})
	t.Cleanup(func() { _ = tr.(interface{ Close() error }).Close() })
	c, err := tr.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = c.Close(); review8f4cWait(t, done) })
	_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	_ = c.SetWriteDeadline(time.Time{})
	go func() { defer close(done); _, _ = c.Read(make([]byte, 1)) }()
	select {
	case <-done:
	case <-time.After(120 * time.Millisecond):
		t.Error("clearing the H3 write deadline erased the active read deadline")
	}
}

func TestReview8f4cInnerTLSSetupBudgetCoversCarrierHeaders(t *testing.T) {
	review8f4cIdentity(t)
	dir := t.TempDir()
	cert, fp, err := transport.LoadOrCreateCert(filepath.Join(dir, "fixture-cert.pem"), filepath.Join(dir, "fixture-key.pem"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requested := make(chan struct{})
	var once sync.Once
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(requested) })
		<-r.Context().Done() // intentionally never return carrier headers
	})}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = server.Serve(pc) }()
	t.Cleanup(func() { _ = server.Close(); _ = pc.Close(); review8f4cWait(t, serverDone) })
	carrier := transport.NewH3(transport.H3Options{ServerAddr: pc.LocalAddr().String(), Fingerprint: fp, DialTimeout: time.Second})
	t.Cleanup(func() { _ = carrier.(interface{ Close() error }).Close() })
	wrapper, err := WithInnerTLS(carrier, []string{strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	setup, cancelSetup := context.WithCancel(t.Context())
	lifetime, cancelLifetime := context.WithCancel(t.Context())
	done := make(chan struct{})
	t.Cleanup(func() { cancelSetup(); cancelLifetime(); review8f4cWait(t, done) })
	go func() {
		defer close(done)
		c, _ := wrapper.(transport.SetupDialer).DialSetup(setup, lifetime)
		if c != nil {
			_ = c.Close()
		}
	}()
	review8f4cWait(t, requested)
	cancelSetup()
	select {
	case <-done:
	case <-time.After(120 * time.Millisecond):
		t.Error("inner TLS setup cancellation never reached H3 while it was waiting for carrier headers")
	}
}

func TestReview8f4cNonMuxSecureStreamPreservesHalfClose(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	s, err := protocol.ClientSideSecureStream(left, review8f4cToken, protocol.RandomSalt(), protocol.ProfileParams{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(s).(interface{ CloseWrite() error }); !ok {
		t.Error("returned nonmux SecureStream loses CloseWrite; streamio.Pipe closes both directions on upload EOF")
	}
}

func TestReview8f4cMuxHalfCloseKeepsBufferedDownload(t *testing.T) {
	left, right := net.Pipe()
	peer, err := smux.Server(right, muxConfig())
	if err != nil {
		t.Fatal(err)
	}
	p := newMuxPool(func(context.Context) (net.Conn, error) { return left, nil }, 1, time.Second)
	t.Cleanup(func() { _ = p.Close(); _ = peer.Close() })
	c, err := p.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	remote, err := peer.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("buffered-download-fixture"), 4096)
	sent := make(chan error, 1)
	go func() {
		_, err := remote.Write(want)
		if err == nil {
			err = remote.CloseWrite()
		}
		sent <- err
	}()
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loopback download fixture did not finish its write half")
	}
	// This is the Pipe upload worker finishing while its download worker has
	// not yet consumed the response that arrived before the remote FIN.
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.(*smux.Stream).GetDieCh():
	case <-time.After(time.Second):
		t.Fatal("fixture did not reach both-FIN cleanup")
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("clean mux half-close discarded buffered download: got=%d want=%d err=%v", len(got), len(want), err)
	}
}

type review8f4cBlockingClose struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type review8f4cGatedWrite struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *review8f4cGatedWrite) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.Conn.Write(b)
}

func TestReview8f4cMuxBurstReservesStreamCapacity(t *testing.T) {
	left, right := net.Pipe()
	peer, err := smux.Server(right, muxConfig())
	if err != nil {
		t.Fatal(err)
	}
	gated := &review8f4cGatedWrite{Conn: left, started: make(chan struct{}), release: make(chan struct{})}
	p := newMuxPool(func(context.Context) (net.Conn, error) { return gated, nil }, 1, time.Second)
	p.softCap = 1
	entry, err := p.createSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.add(entry); err != nil {
		t.Fatal(err)
	}
	results := make(chan net.Conn, 2)
	t.Cleanup(func() { _ = p.Close(); _ = peer.Close() })
	go func() { c, _ := p.Open(t.Context()); results <- c }()
	review8f4cWait(t, gated.started)
	// While the first SYN write is blocked, the already selected session has
	// NumStreams()==0. A second caller can select it as well, with no reserved
	// capacity, and both are committed after the write gate opens.
	selected := p.pick()
	if selected != entry {
		close(gated.release)
		c := <-results
		if c != nil {
			_ = c.Close()
		}
		return // reservation prevented a second selection
	}
	go func() { c, _ := selected.sess.OpenStream(); results <- c }()
	close(gated.release)
	for range 2 {
		select {
		case c := <-results:
			if c == nil {
				t.Fatal("sanitized burst setup unexpectedly failed")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("sanitized burst setup did not complete")
		}
	}
	if n := entry.sess.NumStreams(); n > p.softCap {
		t.Errorf("concurrent stream setup exceeded spillover budget: streams=%d softCap=%d", n, p.softCap)
	}
}

func (c *review8f4cBlockingClose) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Conn.Close()
}

func TestReview8f4cIdleRetirementDoesNotHoldAdaptiveMutex(t *testing.T) {
	left, right := net.Pipe()
	blocking := &review8f4cBlockingClose{Conn: left, entered: make(chan struct{}), release: make(chan struct{})}
	a := NewAdaptive("", transport.WSTLSOptions{}, "auto", time.Second)
	cl := a.build(0)
	cl.poolOnce.Do(func() {
		cl.pool = newMuxPool(func(context.Context) (net.Conn, error) { return blocking, nil }, 1, time.Second)
	})
	entry, err := cl.pool.createSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.pool.add(entry); err != nil {
		t.Fatal(err)
	}
	retired := make(chan struct{})
	queried := make(chan struct{})
	t.Cleanup(func() {
		close(blocking.release)
		_ = right.Close()
		review8f4cWait(t, retired)
		review8f4cWait(t, queried)
		_ = a.Close()
	})
	go func() { defer close(retired); a.NetworkChanged() }()
	review8f4cWait(t, blocking.entered)
	go func() { defer close(queried); _ = a.Current() }()
	select {
	case <-queried:
	case <-time.After(120 * time.Millisecond):
		t.Error("idle carrier close holds Adaptive.mu, blocking every new dial and status query")
	}
}

func TestReview8f4cCorruptUpdateCannotBlockExplicitProxyRestore(t *testing.T) {
	binary := os.Getenv("OTU_INTERNAL_REVIEW_FIXTURE")
	if binary == "" {
		t.Skip("requires a newly built, temporary -tags=netenvfixture otu-client executable")
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	fixture := false
	for _, setting := range info.Settings {
		if setting.Key == "-tags" {
			for _, tag := range strings.FieldsFunc(setting.Value, func(r rune) bool { return r == ',' || r == ' ' }) {
				fixture = fixture || tag == "netenvfixture"
			}
		}
	}
	if !fixture {
		t.Fatal("review refuses to run a client without compile-time registry-free provenance")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, version.ProductName)
	if err := os.MkdirAll(filepath.Join(state, "updates"), 0o700); err != nil {
		t.Fatal(err)
	}
	networkState := filepath.Join(dir, version.NetworkStateName())
	if err := os.MkdirAll(networkState, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, raw string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	settings := filepath.Join(dir, "sanitized-settings.json")
	write(settings, `{"keys":{"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings":{"ProxyEnable":{"exists":true,"kind":4,"integer":1},"ProxyServer":{"exists":true,"kind":1,"text":"127.0.0.1:18080"},"ProxyOverride":{"exists":true,"kind":1,"text":"localhost;127.0.0.1;<local>"}}}}`)
	snapshot := filepath.Join(networkState, "snapshot.json")
	write(snapshot, `{"proxy_enable":0,"proxy_server":{"exists":false},"proxy_override":{"exists":false},"autoconfig_url":{"exists":false},"otu_applied_server":"127.0.0.1:18080"}`)
	write(filepath.Join(state, "updates", "update-transaction.json"), `{"version":`)
	config := filepath.Join(dir, "unused-restore-config.toml")
	write(config, "# sanitized restore-only fixture\n")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--restore", "-c", config)
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		upper := strings.ToUpper(key)
		if upper != "LOCALAPPDATA" && upper != "OTU_NETENV_FIXTURE" && !strings.HasPrefix(upper, "OTU_UPDATE_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "LOCALAPPDATA="+dir, "OTU_NETENV_FIXTURE="+settings)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture restore command failed: %v; %s", err, output)
	}
	if _, err := os.Stat(snapshot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("explicit --restore left the synthetic dead-proxy journal untouched: %s", strings.TrimSpace(string(output)))
	}
	// Control: the identical synthetic proxy journal is recoverable when the
	// independent, corrupt updater journal is absent. Remove only this test's
	// temporary fault injection, not any installed recovery evidence.
	if err := os.Remove(filepath.Join(state, "updates", "update-transaction.json")); err != nil {
		t.Fatal(err)
	}
	control := exec.CommandContext(ctx, binary, "--restore", "-c", config)
	control.Env = append([]string(nil), cmd.Env...)
	output, err = control.CombinedOutput()
	if err != nil {
		t.Fatalf("control fixture recovery failed: %v; %s", err, output)
	}
	if _, err := os.Stat(snapshot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("control fixture did not recover its journal: %v; %s", err, output)
	}
}
