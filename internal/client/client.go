// Package client drives outbound tunnel connections: it opens the configured
// transport, authenticates, exchanges a session salt, and speaks the inner
// AEAD protocol toward targets. With Mux enabled it multiplexes every target
// over a small pool of warm sessions.
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

type Options struct {
	RequireChannelAuth bool // independent TLS exporter-bound v6; no legacy fallback
	IdentityScope      string
	Token              string
	DialTimeout        time.Duration // per-connection budget for handshake+target
	Profile            string        // fast | balanced | stealth (shaping on our writes)
	Mux                bool          // multiplex targets over pooled sessions
	// MuxByteCap overrides the per-session rotation byte cap (0 = default
	// 160 MiB). Rotation stops new streams; active downloads can outlive the hint
	// and remain subject to the external front's request limits.
	MuxByteCap  int64
	MuxSessions int // warm-session cap; zero uses the general default
	// OnAuthRejected is invoked when the server rejects the device token
	// (unknown/purged/expired) so the caller can re-register with the panel.
	OnAuthRejected func()
}

type Client struct {
	Transport  transport.Transport
	opts       Options
	setupError error // capacity/closed sentinel; never opens identity or transport

	poolOnce           sync.Once
	poolMu             sync.Mutex
	pool               *MuxPool
	transportCloseOnce sync.Once
	transportCloseErr  error
	lifecycleMu        sync.Mutex
	closed             bool
	draining           bool
	drainOnce          sync.Once
	shutdownOnce       sync.Once
	shutdownDone       chan struct{}
	shutdownErr        error
	setupCtx           context.Context
	cancelSetups       context.CancelFunc
	connections        map[*clientOwnedConn]struct{} // mux and nonmux carriers stay owned through drain/shutdown
	mu                 sync.RWMutex
	banInfo            string // last "banned:reason" or "kicked:reason" from token check
	banAt              time.Time
}

// banRefreshInterval bounds how long a cached banned/kicked verdict sticks
// without re-checking: the client short-circuits dials while banned, but a
// device that gets unbanned/unkicked mid-session must recover without a
// restart. One handshake per minute worst case is cheap.
const banRefreshInterval = time.Minute

func New(t transport.Transport, token string) *Client {
	return &Client{Transport: t, opts: Options{Token: token}}
}

func NewWithOptions(t transport.Transport, o Options) *Client { return &Client{Transport: t, opts: o} }

func (c *Client) perDeviceToken() string {
	store, err := NewPoolTokenStore(c.opts.IdentityScope)
	if err != nil {
		return ""
	}
	df, err := store.LoadOrCreate()
	if err != nil {
		return ""
	}
	return df.Token
}

// authCandidates orders the credentials to try at the handshake: an
// explicitly configured shared token first (legacy/no-panel servers), then
// the per-device token (panel mode). Fresh installs have no configured
// token, so only the device token is tried — no shared secret in the binary.
func (c *Client) authCandidates() []string {
	if c.opts.IdentityScope != "" {
		if token := c.perDeviceToken(); token != "" {
			return []string{token}
		}
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range []string{c.opts.Token, c.perDeviceToken()} {
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// signHandshake produces the v5 proof-of-possession signature over
// (token, salt) using the device's registered ed25519 key. Returns false
// when no usable key exists (fresh/pending identity): the dial then falls
// back to the unsigned v4 handshake.
func (c *Client) signHandshake(token string, salt []byte) ([]byte, bool) {
	return c.signDeviceMessage(protocol.HandshakeMsg(token, salt))
}

func (c *Client) signDeviceMessage(msg []byte) ([]byte, bool) {
	ts, err := NewPoolTokenStore(c.opts.IdentityScope)
	if err != nil {
		return nil, false
	}
	if _, err := ts.EnsureSSHKey(); err != nil {
		return nil, false
	}
	pemBytes, err := privatefile.Read(ts.SSHPrivatePath(), 16<<10)
	if err != nil {
		return nil, false
	}
	// The device key is written by ssh.MarshalPrivateKey (OPENSSH
	// format), so parse it with the ssh package rather than PKCS8.
	keyAny, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, false
	}
	var ed ed25519.PrivateKey
	switch k := keyAny.(type) {
	case ed25519.PrivateKey:
		ed = k
	case *ed25519.PrivateKey:
		ed = *k
	default:
		return nil, false
	}
	return ed25519.Sign(ed, msg), true
}

// dialAndAuth opens one transport connection and runs the handshake with
// authTok. The caller owns the returned conn on success. A non-nil salt
// means it was carried (and is already replayed-protected) inside a v5
// handshake; nil means the caller writes it as usual (v4 flow).
func (c *Client) dialAndAuth(ctx context.Context, authTok string, timeout time.Duration) (net.Conn, []byte, error) {
	setup, finish, err := c.beginSetup(ctx, timeout)
	if err != nil {
		return nil, nil, err
	}
	defer finish()
	return c.dialAndAuthSetup(setup, ctx, authTok)
}

func (c *Client) dialAndAuthSetup(ctx, lifetime context.Context, authTok string) (net.Conn, []byte, error) {
	salt := protocol.RandomSalt()
	sig, signed := c.signHandshake(authTok, salt)
	if !signed && (c.opts.IdentityScope != "" || c.opts.RequireChannelAuth) {
		return nil, nil, errors.New("client: trusted pool requires the scoped Ed25519 device key; unsigned downgrade refused")
	}
	carrier, cancelCarrier, err := dialSetupCarrier(c.Transport, ctx, lifetime)
	if err != nil {
		return nil, nil, fmt.Errorf("client: transport dial: %w", err)
	}
	raw, err := c.adoptConnectionWithCancel(carrier, cancelCarrier)
	if err != nil {
		return nil, nil, err
	}
	finishIO, err := bindSetupIO(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			transport.AbortSetup(raw)
		}
	}()
	ready := func() (net.Conn, []byte, error) {
		if err := finishIO(); err != nil {
			return nil, nil, err
		}
		succeeded = true
		return raw, salt, nil
	}
	if c.opts.RequireChannelAuth {
		inner, ok := carrier.(*tls.Conn)
		if !ok {
			transport.AbortSetup(raw)
			return nil, nil, errors.New("connection-bound session requires independent TLS; no token sent")
		}
		binding, err := protocol.ChannelBinding(inner.ConnectionState())
		if err != nil {
			transport.AbortSetup(raw)
			return nil, nil, err
		}
		msg, err := protocol.ChannelHandshakeMsg(authTok, salt, binding)
		if err != nil {
			transport.AbortSetup(raw)
			return nil, nil, err
		}
		sig, ok := c.signDeviceMessage(msg)
		if !ok {
			transport.AbortSetup(raw)
			return nil, nil, errors.New("connection-bound device key unavailable")
		}
		if err := protocol.WriteChannelHandshake(raw, authTok, salt, sig); err != nil {
			transport.AbortSetup(raw)
			return nil, nil, err
		}
		ver, status, err := protocol.ReadHandshakeStatus(raw)
		if err != nil {
			transport.AbortSetup(raw)
			return nil, nil, err
		}
		if ver != protocol.ChannelVersion {
			transport.AbortSetup(raw)
			return nil, nil, errors.New("connection-bound version refused; no legacy downgrade")
		}
		if status != protocol.StatusOK {
			transport.AbortSetup(raw)
			return nil, nil, &protocol.AuthError{Status: status}
		}
		return ready()
	}

	if signed {
		if err := protocol.WriteHandshakeV5(raw, authTok, salt, sig); err != nil {
			raw.Close()
			return nil, nil, fmt.Errorf("client: handshake write: %w", err)
		}
		ver, st, err := protocol.ReadHandshakeStatus(raw)
		if err != nil {
			raw.Close()
			return nil, nil, err
		}
		if ver == protocol.ProtoVersionLegacy && st == protocol.StatusBadVersion && c.opts.IdentityScope == "" {
			// Pre-v5 server: retry as the legacy unsigned handshake on the
			// same connection (it never consumed the v5 bytes beyond the
			// version byte it rejected on).
			if err := protocol.WriteHandshake(raw, authTok); err != nil {
				raw.Close()
				return nil, nil, fmt.Errorf("client: handshake write: %w", err)
			}
			ver, st, err = protocol.ReadHandshakeStatus(raw)
			if err != nil {
				raw.Close()
				return nil, nil, err
			}
			salt = nil
		}
		if ver != protocol.ProtoVersion && (c.opts.IdentityScope != "" || ver != protocol.ProtoVersionLegacy) {
			raw.Close()
			return nil, nil, protocol.ErrVersionMismatch
		}
		if st != protocol.StatusOK {
			raw.Close()
			return nil, nil, &protocol.AuthError{Status: st}
		}
		return ready()
	}

	// No device key (fresh identity): the legacy unsigned handshake.
	if err := protocol.WriteHandshake(raw, authTok); err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("client: handshake write: %w", err)
	}
	if err := protocol.ReadAuthResponse(raw); err != nil {
		raw.Close()
		return nil, nil, err
	}
	salt = nil
	return ready()
}

// dialAuthenticated tries each auth candidate on a fresh connection until
// one is accepted; a bad-token rejection falls through to the next candidate.
// Returns the already-sent session salt when the v5 handshake carried it.
func (c *Client) dialAuthenticated(ctx context.Context, timeout time.Duration) (net.Conn, string, []byte, error) {
	setup, finish, err := c.beginSetup(ctx, timeout)
	if err != nil {
		return nil, "", nil, err
	}
	defer finish()
	return c.dialAuthenticatedSetup(setup, ctx)
}

func (c *Client) dialAuthenticatedSetup(ctx, lifetime context.Context) (net.Conn, string, []byte, error) {
	if c.setupError != nil {
		return nil, "", nil, c.setupError
	}
	c.lifecycleMu.Lock()
	unavailable := c.closed || c.draining
	c.lifecycleMu.Unlock()
	if unavailable {
		return nil, "", nil, net.ErrClosed
	}
	candidates := c.authCandidates()
	if len(candidates) == 0 {
		return nil, "", nil, errors.New("client: no auth token available")
	}
	for i, tok := range candidates {
		raw, salt, err := c.dialAndAuthSetup(ctx, lifetime, tok)
		if err == nil {
			return raw, tok, salt, nil
		}
		var ae *protocol.AuthError
		if !errors.As(err, &ae) {
			return nil, "", nil, err // transport/IO failure — surface unchanged
		}
		if ae.Status == protocol.StatusBadToken && i < len(candidates)-1 {
			continue
		}
		return nil, "", nil, c.mapAuthError(err)
	}
	return nil, "", nil, errors.New("client: all auth candidates rejected")
}

// ProbeSession runs one full transport+handshake round trip and closes it:
// the setup-latency sample for health telemetry.
func (c *Client) ProbeSession(ctx context.Context) (time.Duration, error) {
	timeout := c.opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	start := time.Now()
	raw, _, _, err := c.dialAuthenticated(ctx, timeout)
	if err != nil {
		return 0, err
	}
	raw.Close()
	return time.Since(start), nil
}

// mapAuthError translates handshake rejections into typed client errors.
// Unknown/expired tokens trigger re-registration: the device re-enters the
// approval queue instead of failing forever.
func (c *Client) mapAuthError(err error) error {
	var ae *protocol.AuthError
	if !errors.As(err, &ae) {
		return fmt.Errorf("client: auth: %w", err)
	}
	switch ae.Status {
	case protocol.StatusPending:
		return &PendingError{Status: "pending"}
	case protocol.StatusExpired:
		if c.opts.OnAuthRejected != nil {
			c.opts.OnAuthRejected()
		}
		return &PendingError{Status: "expired"}
	case protocol.StatusBanned:
		return &BlockedError{Kind: "banned", Reason: "device banned"}
	case protocol.StatusBadToken:
		// Token unknown to the panel (e.g. purged after inactivity):
		// re-register and wait for approval.
		if c.opts.OnAuthRejected != nil {
			c.opts.OnAuthRejected()
		}
		return &PendingError{Status: "pending"}
	default:
		return fmt.Errorf("client: auth: %w", err)
	}
}

// BlockedError is returned when the server blocks a domain or the peer is banned/kicked.
// The proxy can serve a local block page instead of piping.
type BlockedError struct {
	Reason string
	Kind   string // "blocked", "banned", "kicked"
}

func (e *BlockedError) Error() string { return e.Kind + ": " + e.Reason }

// PendingError means the device token is registered but not yet approved
// (or expired). It is terminal for the adaptive ladder: no other transport
// tier can help, so callers must not escalate.
type PendingError struct{ Status string }

func (e *PendingError) Error() string {
	return "client: device " + e.Status + " — waiting for approval at the panel"
}

// muxSessionFactory performs the full authenticated handshake and switches
// the resulting secure stream into mux mode; the returned conn is handed to
// smux.Client.
func (c *Client) muxSessionFactory(ctx context.Context) (net.Conn, error) {
	setup, finish, err := c.beginSetup(ctx, c.setupBudget())
	if err != nil {
		return nil, err
	}
	defer finish()
	raw, authTok, salt, err := c.dialAuthenticatedSetup(setup, ctx)
	if err != nil {
		return nil, err
	}
	finishIO, err := bindSetupIO(setup, raw)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			transport.AbortSetup(raw)
		}
	}()

	if salt == nil {
		// v4 flow: the salt travels right after the handshake.
		salt = protocol.RandomSalt()
		if err := protocol.WriteSalt(raw, salt); err != nil {
			raw.Close()
			return nil, fmt.Errorf("client: salt write: %w", err)
		}
	}
	sec, err := protocol.ClientSideSecureStream(raw, authTok, salt, protocol.ProfileFor(c.opts.Profile))
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: secure stream: %w", err)
	}
	// Per-device token for panel approval (v4): always sent; "" signals legacy.
	tok := c.perDeviceToken()
	if err := protocol.WriteToken(sec, tok); err != nil {
		sec.Close()
		return nil, fmt.Errorf("client: token write: %w", err)
	}
	if resp, err := protocol.ReadToken(sec); err != nil {
		sec.Close()
		return nil, fmt.Errorf("client: token response: %w", err)
	} else if resp != "ok" {
		// Handle ISP-level states: banned/kicked still establish the session but every request will be blocked with a page
		if resp == "pending" || resp == "expired" {
			sec.Close()
			return nil, &PendingError{Status: resp}
		}
		if len(resp) >= 7 && (resp[:7] == "banned:" || resp[:7] == "kicked:") {
			c.mu.Lock()
			c.banInfo = resp
			c.banAt = time.Now()
			c.mu.Unlock()
			// Still establish mux session, but future dials will be blocked until unban
		} else {
			sec.Close()
			return nil, fmt.Errorf("client: token %s", resp)
		}
	} else {
		c.mu.Lock()
		c.banInfo = ""
		c.mu.Unlock()
		// The panel just confirmed this device is approved over an
		// authenticated channel — the strongest possible signal for the
		// durable ever-approved marker that keeps the live token off
		// system-trusted channels forever after.
		c.markEverApproved()
	}
	if _, err := sec.Write([]byte{protocol.MuxMarker}); err != nil {
		sec.Close()
		return nil, fmt.Errorf("client: mode write: %w", err)
	}
	if err := finishIO(); err != nil {
		return nil, err
	}
	succeeded = true
	return sec, nil
}

func (c *Client) getPool() *MuxPool {
	c.poolOnce.Do(func() {
		c.poolMu.Lock()
		defer c.poolMu.Unlock()
		maxSessions := c.opts.MuxSessions
		if maxSessions <= 0 {
			maxSessions = 4 // four warm + four draining fit the relay's eight-session identity budget
		}
		c.pool = newMuxPool(c.muxSessionFactory, maxSessions, c.opts.DialTimeout)
		if c.opts.MuxByteCap > 0 {
			c.pool.maxBytes = c.opts.MuxByteCap
		}
		context.AfterFunc(c.pool.ctx, func() { _ = c.closeTransportIfIdle() })
	})
	return c.pool
}

// DrainComplete is read without creating a new pool. The adaptive owner must
// keep retired clients until their active transfers finish or explicit close.
func (c *Client) DrainComplete() bool {
	c.poolMu.Lock()
	pool := c.pool
	c.poolMu.Unlock()
	if pool != nil {
		pool.mu.Lock()
		dead := pool.retireLocked(time.Now())
		finished := pool.closed && !pool.dialing && len(pool.sessions) == 0
		pool.mu.Unlock()
		if len(dead) > 0 || finished {
			c.startDrainWorker(pool, dead)
		}
	}
	c.lifecycleMu.Lock()
	active := len(c.connections)
	c.lifecycleMu.Unlock()
	if active > 0 {
		return false
	}
	if pool == nil {
		return true
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.closed && !pool.dialing && len(pool.sessions) == 0
}

func (c *Client) Drain() {
	if c.setupError != nil {
		return
	}
	c.lifecycleMu.Lock()
	c.draining = true
	if c.cancelSetups != nil {
		c.cancelSetups()
	}
	c.lifecycleMu.Unlock()
	pool := c.getPool()
	pool.beginDrain()
	c.startDrainWorker(pool, nil)
}

func (c *Client) startDrainWorker(pool *MuxPool, initial []*muxEntry) {
	// Initial closes may be discovered by a status read after the worker ran.
	// Let the pool own that bounded set; never close it synchronously under a.mu.
	if len(initial) > 0 {
		go func() {
			for _, entry := range initial {
				_ = entry.sess.Close()
			}
		}()
	}
	c.drainOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				pool.retire()
				_ = c.closeTransportIfIdle()
				pool.mu.Lock()
				finished := pool.closed && !pool.dialing && len(pool.sessions) == 0
				pool.mu.Unlock()
				if finished {
					return
				}
				select {
				case <-pool.ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	})
}

func (c *Client) closeTransport() error {
	c.transportCloseOnce.Do(func() {
		if closer, ok := c.Transport.(interface{ Close() error }); ok {
			c.transportCloseErr = closer.Close()
		}
	})
	return c.transportCloseErr
}

func (c *Client) Close() error {
	done := c.startClose()
	<-done
	return c.shutdownErr
}

// A retired client remains owned until this completion signal closes. Adaptive
// bookkeeping must not wait for network teardown while holding its mutex.
func (c *Client) startClose() <-chan struct{} {
	c.lifecycleMu.Lock()
	if c.shutdownDone == nil {
		c.shutdownDone = make(chan struct{})
	}
	done := c.shutdownDone
	c.closed = true
	if c.cancelSetups != nil {
		c.cancelSetups()
	}
	c.lifecycleMu.Unlock()
	c.shutdownOnce.Do(func() {
		go func() { c.shutdownErr = c.closeNow(); close(done) }()
	})
	return done
}

func (c *Client) closeNow() error {
	if c.setupError != nil {
		return nil
	}
	c.lifecycleMu.Lock()
	connections := make([]*clientOwnedConn, 0, len(c.connections))
	for conn := range c.connections {
		connections = append(connections, conn)
	}
	c.lifecycleMu.Unlock()
	err := c.getPool().Close()
	for _, conn := range connections {
		err = errors.Join(err, conn.CloseNow())
	}
	return errors.Join(err, c.closeTransport())
}

type clientOwnedConn struct {
	net.Conn
	owner    *Client
	once     sync.Once
	closeErr error
	cancel   context.CancelFunc
}

func (c *Client) adoptConnection(raw net.Conn) (net.Conn, error) {
	return c.adoptConnectionWithCancel(raw, nil)
}

func (c *Client) adoptConnectionWithCancel(raw net.Conn, cancel context.CancelFunc) (net.Conn, error) {
	c.lifecycleMu.Lock()
	if c.closed || c.draining {
		c.lifecycleMu.Unlock()
		transport.AbortSetup(raw)
		if cancel != nil {
			cancel()
		}
		return nil, net.ErrClosed
	}
	owned := &clientOwnedConn{Conn: raw, owner: c, cancel: cancel}
	if c.connections == nil {
		c.connections = map[*clientOwnedConn]struct{}{}
	}
	c.connections[owned] = struct{}{}
	c.lifecycleMu.Unlock()
	return owned, nil
}
func (c *clientOwnedConn) Close() error {
	return c.close(false)
}

func (c *clientOwnedConn) CloseNow() error {
	return c.close(true)
}

func (c *clientOwnedConn) close(immediate bool) error {
	c.once.Do(func() {
		if immediate {
			_ = c.Conn.SetDeadline(time.Now())
			if closer, ok := c.Conn.(interface{ CloseNow() error }); ok {
				c.closeErr = closer.CloseNow()
			} else {
				c.closeErr = c.Conn.Close()
			}
		} else {
			c.closeErr = c.Conn.Close()
		}
		if c.cancel != nil {
			c.cancel()
		}
		c.owner.lifecycleMu.Lock()
		delete(c.owner.connections, c)
		c.owner.lifecycleMu.Unlock()
		_ = c.owner.closeTransportIfIdle()
	})
	return c.closeErr
}
func (c *clientOwnedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}
func (c *Client) closeTransportIfIdle() error {
	c.lifecycleMu.Lock()
	idle := (c.closed || c.draining) && len(c.connections) == 0
	c.lifecycleMu.Unlock()
	if idle {
		return c.closeTransport()
	}
	return nil
}

// DialTunnel returns an AEAD-secured stream connected to target via the
// server. It implements proxy.Dialer.
func (c *Client) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	if c.setupError != nil {
		return nil, c.setupError
	}
	// ISP-level ban/kick: if peer is banned/kicked, show block page for any site and schedule 10min kick
	c.mu.RLock()
	ban := c.banInfo
	banAt := c.banAt
	c.mu.RUnlock()
	if ban != "" {
		// Verdicts refresh: a device unbanned/unkicked mid-session recovers
		// on the next dial after the interval instead of staying blocked
		// until restart.
		if time.Since(banAt) > banRefreshInterval {
			c.mu.Lock()
			if c.banInfo == ban {
				c.banInfo = ""
			}
			c.mu.Unlock()
		} else {
			if len(ban) >= 7 && ban[:7] == "banned:" {
				return nil, &BlockedError{Kind: "banned", Reason: ban[7:]}
			}
			if len(ban) >= 7 && ban[:7] == "kicked:" {
				reason := ban[7:]
				// silent: prefix means silent kick - just close, no page
				if len(reason) >= 7 && reason[:7] == "silent:" {
					return nil, &BlockedError{Kind: "kicked-silent", Reason: reason[7:]}
				}
				return nil, &BlockedError{Kind: "kicked", Reason: reason}
			}
		}
	}
	setup, finish, err := c.beginSetup(ctx, c.setupBudget())
	if err != nil {
		return nil, err
	}
	defer finish()

	var rw net.Conn
	if c.opts.Mux {
		stream, err := c.getPool().Open(setup)
		if err != nil {
			return nil, fmt.Errorf("client: mux open: %w", err)
		}
		rw = stream
	} else {
		raw, err := c.legacyConnectSetup(setup, ctx)
		if err != nil {
			return nil, err
		}
		rw = raw
	}

	finishIO, err := bindSetupIO(setup, rw)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			transport.AbortSetup(rw)
		}
	}()
	if err := protocol.WriteTarget(rw, target); err != nil {
		rw.Close()
		return nil, fmt.Errorf("client: target write: %w", err)
	}
	if err := protocol.ReadTargetResponse(rw); err != nil {
		// Check for ISP block/ban statuses
		if se, ok := err.(*protocol.StatusError); ok {
			if se.Status == protocol.StatusBlocked {
				// Try to read block reason
				reason := ""
				if tok, terr := protocol.ReadToken(rw); terr == nil {
					reason = tok
				}
				rw.Close()
				// Map to BlockedError with kind
				kind := "blocked"
				if len(reason) >= 7 && reason[:7] == "banned:" {
					kind = "banned"
					reason = reason[7:]
				} else if len(reason) >= 7 && reason[:7] == "kicked:" {
					kind = "kicked"
					reason = reason[7:]
					if len(reason) >= 7 && reason[:7] == "silent:" {
						kind = "kicked-silent"
						reason = reason[7:]
					}
				} else if len(reason) >= 8 && reason[:8] == "blocked:" {
					kind = "blocked"
					reason = reason[8:]
					// Kill-switch down page: "down:<admin reason>" renders a
					// distinct "traffic temporarily down" notice, not a
					// domain block notice.
					if len(reason) >= 5 && reason[:5] == "down:" {
						kind = "down"
						reason = reason[5:]
					}
				}
				return nil, &BlockedError{Kind: kind, Reason: reason}
			}
			if se.Status == protocol.StatusBanned {
				reason := ""
				if tok, terr := protocol.ReadToken(rw); terr == nil {
					reason = tok
				}
				rw.Close()
				return nil, &BlockedError{Kind: "banned", Reason: reason}
			}
		}
		rw.Close()
		return nil, fmt.Errorf("client: connect %s: %w", target, err)
	}
	if err := finishIO(); err != nil {
		return nil, err
	}
	succeeded = true
	return rw, nil
}

// legacyConnect runs the v1-style flow: one transport connection per target;
// the ATYP byte of the target request doubles as the implicit mode marker.
func (c *Client) legacyConnect(ctx context.Context) (*protocol.SecureStream, error) {
	setup, finish, err := c.beginSetup(ctx, c.setupBudget())
	if err != nil {
		return nil, err
	}
	defer finish()
	return c.legacyConnectSetup(setup, ctx)
}

func (c *Client) legacyConnectSetup(ctx, lifetime context.Context) (*protocol.SecureStream, error) {
	raw, authTok, salt, err := c.dialAuthenticatedSetup(ctx, lifetime)
	if err != nil {
		return nil, err
	}
	finishIO, err := bindSetupIO(ctx, raw)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			transport.AbortSetup(raw)
		}
	}()

	if salt == nil {
		// v4 flow: the salt travels right after the handshake.
		salt = protocol.RandomSalt()
		if err := protocol.WriteSalt(raw, salt); err != nil {
			raw.Close()
			return nil, fmt.Errorf("client: salt write: %w", err)
		}
	}
	sec, err := protocol.ClientSideSecureStream(raw, authTok, salt, protocol.ProfileFor(c.opts.Profile))
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: secure stream: %w", err)
	}
	// Per-device token (v4): always sent; server reads it unconditionally.
	if err := protocol.WriteToken(sec, c.perDeviceToken()); err != nil {
		sec.Close()
		return nil, fmt.Errorf("client: token write: %w", err)
	}
	if resp, err := protocol.ReadToken(sec); err != nil {
		sec.Close()
		return nil, fmt.Errorf("client: token response: %w", err)
	} else if resp != "ok" {
		if resp == "pending" || resp == "expired" {
			sec.Close()
			return nil, &PendingError{Status: resp}
		}
		if len(resp) >= 7 && (resp[:7] == "banned:" || resp[:7] == "kicked:") {
			c.mu.Lock()
			c.banInfo = resp
			c.banAt = time.Now()
			c.mu.Unlock()
		} else {
			sec.Close()
			return nil, fmt.Errorf("client: token %s", resp)
		}
	} else {
		c.mu.Lock()
		c.banInfo = ""
		c.mu.Unlock()
		c.markEverApproved()
	}
	if err := finishIO(); err != nil {
		return nil, err
	}
	succeeded = true
	return sec, nil
}

// markEverApproved records the durable approval marker for this device
// (fingerprint-keyed), keeping the live token off system-trusted channels
// from this point on — across restarts and re-registrations.
func (c *Client) markEverApproved() {
	store, err := NewPoolTokenStore(c.opts.IdentityScope)
	if err != nil {
		return
	}
	df, err := store.LoadOrCreate()
	if err != nil {
		return
	}
	store.MarkApproved(df.Fingerprint)
}

// OpenUDPRelay returns a stream speaking the framed UDP relay protocol
// ([u16][ATYP addr port][payload] per datagram). Requires Mux.
func (c *Client) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	if c.setupError != nil {
		return nil, c.setupError
	}
	if !c.opts.Mux {
		return nil, fmt.Errorf("client: udp relay requires mux = true")
	}
	setup, finish, err := c.beginSetup(ctx, c.setupBudget())
	if err != nil {
		return nil, err
	}
	defer finish()
	stream, err := c.getPool().Open(setup)
	if err != nil {
		return nil, err
	}
	finishIO, err := bindSetupIO(setup, stream)
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write([]byte{protocol.UdpMarker}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("client: udp mode write: %w", err)
	}
	if err := finishIO(); err != nil {
		return nil, err
	}
	return stream, nil
}
