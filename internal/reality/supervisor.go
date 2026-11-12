package reality

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"opentunnel/internal/privatefile"
)

type ProcessOptions struct {
	Executable string
	SHA256     string
	StateDir   string
	Listen     string
	Target     string
	Config     []byte
	// Mode is client or server; each has a strict generated-config validator.
	Mode         string
	ReadyTimeout time.Duration
}

// Supervisor owns only its verified, privately staged companion process. It
// never attaches to or kills a pre-existing listener. It restarts on failure
// with bounded backoff and kills/reaps the child on cancellation/host death.
type Supervisor struct {
	o                       ProcessOptions
	ctx                     context.Context
	cancel                  context.CancelFunc
	mu                      sync.Mutex
	process                 *exec.Cmd
	ready                   bool
	closed                  bool
	started                 chan error
	startOnce               sync.Once
	done                    chan struct{}
	dir, executable, config string
	remove                  func()
}

func Start(ctx context.Context, o ProcessOptions) (*Supervisor, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch o.Mode {
	case "client":
		if err := ValidateClientJSON(o.Config, o.Listen, o.Target); err != nil {
			return nil, err
		}
	case "server":
		if err := ValidateServerJSON(o.Config, o.Listen, o.Target); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid companion mode")
	}
	if o.ReadyTimeout <= 0 {
		o.ReadyTimeout = 15 * time.Second
	}
	if o.ReadyTimeout > time.Minute {
		return nil, errors.New("invalid companion readiness budget")
	}
	if err := privatefile.EnsureDir(o.StateDir); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(o.StateDir, "managed-xray-")
	if err != nil {
		return nil, err
	}
	if err := privatefile.EnsureDir(dir); err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	s := &Supervisor{o: o, started: make(chan error, 1), done: make(chan struct{}), dir: dir}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.config = filepath.Join(dir, "runtime.json")
	name := "otu-xray"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	s.executable = filepath.Join(dir, name)
	s.remove = func() { _ = os.Remove(s.config); _ = os.Remove(s.executable); _ = os.Remove(dir) }
	if err := stageExecutable(o.Executable, s.executable, o.SHA256); err != nil {
		s.cancel()
		s.remove()
		return nil, err
	}
	if err := privatefile.WriteNew(s.config, o.Config); err != nil {
		s.cancel()
		s.remove()
		return nil, err
	}
	if err := s.preflight(); err != nil {
		s.cancel()
		s.remove()
		return nil, err
	}
	go s.loop()
	select {
	case err := <-s.started:
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		return s, nil
	case <-ctx.Done():
		_ = s.Close()
		return nil, ctx.Err()
	}
}

func stageExecutable(source, destination, expected string) error {
	want, err := hex.DecodeString(expected)
	if err != nil || len(want) != sha256.Size {
		return errors.New("companion requires an explicit SHA-256 digest")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return errors.New("companion executable unavailable")
	}
	if !info.Mode().IsRegular() || info.Size() < 1024 || info.Size() > 96<<20 {
		return errors.New("invalid companion executable file")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, 96<<20+1))
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != info.Size() || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), expected) {
		return errors.New("companion digest mismatch; refusing launch")
	}
	if err := privatefile.Protect(destination); err != nil {
		return err
	}
	return executableMode(destination)
}

func (s *Supervisor) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, s.executable, args...)
	cmd.Dir = s.dir
	cmd.Env = companionEnvironment(s.dir)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	prepareProcess(cmd)
	return cmd
}

func companionEnvironment(dir string) []string {
	env := []string{"TMP=" + dir, "TEMP=" + dir, "TMPDIR=" + dir, "GOMAXPROCS=4"}
	for _, key := range []string{"SystemRoot", "WINDIR", "USERPROFILE", "LOCALAPPDATA", "HOME"} {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	// No inherited XRAY_*/V2RAY_* config overrides, TLS key logs, proxy
	// environment, agent secrets or user PATH executable resolution.
	return env
}

func (s *Supervisor) preflight() error {
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	cmd := s.command(ctx, "version")
	var out boundedText
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil || !strings.HasPrefix(out.String(), "opentunnel-xray "+Version+" ") {
		return errors.New("companion version preflight failed")
	}
	if err := s.command(ctx, "run", "-test", "-c", s.config).Run(); err != nil {
		return errors.New("companion config preflight failed (details withheld)")
	}
	return nil
}

type boundedText struct{ b []byte }

func (b *boundedText) Write(p []byte) (int, error) {
	n := len(p)
	room := 512 - len(b.b)
	if room > 0 {
		b.b = append(b.b, p[:min(room, n)]...)
	}
	return n, nil
}
func (b *boundedText) String() string { return string(b.b) }

func (s *Supervisor) loop() {
	defer close(s.done)
	defer s.remove()
	defer func() {
		s.mu.Lock()
		s.ready = false
		s.mu.Unlock()
	}()
	backoff := time.Second
	for s.ctx.Err() == nil {
		startedAt := time.Now()
		err := s.runOnce()
		initialFailure := false
		s.startOnce.Do(func() { s.started <- err; initialFailure = true })
		if initialFailure {
			return
		}
		if s.ctx.Err() != nil {
			return
		}
		if time.Since(startedAt) > time.Minute {
			backoff = time.Second
		}
		s.mu.Lock()
		s.ready = false
		s.mu.Unlock()
		timer := time.NewTimer(backoff)
		select {
		case <-s.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (s *Supervisor) runOnce() error {
	// Verify the staged digest again before each restart; staging alone is
	// not authority to execute a file modified by a competing process.
	if err := verifyExecutableDigest(s.executable, s.o.SHA256); err != nil {
		return err
	}
	config, err := privatefile.Read(s.config, 64<<10)
	if err != nil || !bytes.Equal(config, s.o.Config) {
		return errors.New("private companion config changed; refusing restart")
	}
	ln, err := net.Listen("tcp", s.o.Listen)
	if err != nil {
		return errors.New("companion listener already owned; refusing attachment")
	}
	_ = ln.Close()
	cmd := s.command(s.ctx, "run", "-c", s.config)
	if err := cmd.Start(); err != nil {
		return errors.New("companion process creation failed")
	}
	release, err := containProcess(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("companion containment unavailable: %w", err)
	}
	defer release()
	s.mu.Lock()
	s.process = cmd
	s.ready = false
	s.mu.Unlock()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.NewTimer(s.o.ReadyTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	ready := false
	for !ready {
		select {
		case <-s.ctx.Done():
			_ = cmd.Process.Kill()
			<-exited
			return s.ctx.Err()
		case <-deadline.C:
			_ = cmd.Process.Kill()
			<-exited
			return errors.New("companion readiness timed out")
		case <-exited:
			return errors.New("companion exited before readiness")
		case <-tick.C:
			c, err := net.DialTimeout("tcp", s.o.Listen, 100*time.Millisecond)
			if err == nil {
				_ = c.Close()
				ready = true
			}
		}
	}
	// Require a brief stable listener before exposing readiness. A bind
	// that disappears immediately or a process failing startup is not ready.
	stable := time.NewTimer(150 * time.Millisecond)
	select {
	case <-s.ctx.Done():
		stable.Stop()
		_ = cmd.Process.Kill()
		<-exited
		return s.ctx.Err()
	case <-exited:
		stable.Stop()
		return errors.New("companion exited during readiness check")
	case <-stable.C:
	}
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()
	s.startOnce.Do(func() { s.started <- nil })
	select {
	case <-s.ctx.Done():
		_ = cmd.Process.Kill()
		<-exited
		return s.ctx.Err()
	case <-exited:
		return nil
	}
}

func verifyExecutableDigest(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1024 || info.Size() > 96<<20 {
		return errors.New("staged companion unavailable or invalid")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("staged companion unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("staged companion changed while opening")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, 96<<20+1))
	if err != nil || n != info.Size() || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return errors.New("staged companion digest changed")
	}
	return nil
}

// WaitReady gives dialers shared backoff/readiness instead of launching one
// process per browser request. TCP readiness alone is not an outer-auth test.
func (s *Supervisor) WaitReady(ctx context.Context) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.ctx.Err() != nil {
			return net.ErrClosed
		}
		s.mu.Lock()
		ready, closed := s.ready, s.closed
		s.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return net.ErrClosed
		case <-ticker.C:
		}
	}
}
func (s *Supervisor) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	<-s.done
	return nil
}

// SOCKSOptions returns the private local auth from a validated client document.
func SOCKSOptions(config []byte) (*proxy.Auth, error) {
	var d document
	if decodeStrict(config, &d) != nil || len(d.Inbounds) != 1 {
		return nil, errors.New("invalid companion config")
	}
	var local socksSettings
	if decodeStrict(d.Inbounds[0].Settings, &local) != nil || len(local.Accounts) != 1 {
		return nil, errors.New("invalid companion authentication")
	}
	return &proxy.Auth{User: local.Accounts[0].User, Password: local.Accounts[0].Pass}, nil
}
