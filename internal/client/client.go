// Package client drives outbound tunnel connections: it opens the configured
// transport, authenticates, exchanges a session salt, and speaks the inner
// AEAD protocol toward targets. With Mux enabled it multiplexes every target
// over a small pool of warm sessions.
package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

type Options struct {
	Token       string
	DialTimeout time.Duration // per-connection budget for handshake+target
	Profile     string        // fast | balanced | stealth (shaping on our writes)
	Mux         bool          // multiplex targets over pooled sessions
	// OnAuthRejected is invoked when the server rejects the device token
	// (unknown/purged/expired) so the caller can re-register with the panel.
	OnAuthRejected func()
}

type Client struct {
	Transport transport.Transport
	opts      Options

	poolOnce sync.Once
	pool     *MuxPool
	mu       sync.RWMutex
	banInfo  string // last "banned:reason" or "kicked:reason" from token check
	banAt    time.Time
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
	store, err := NewTokenStore()
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
	ts, err := NewTokenStore()
	if err != nil {
		return nil, false
	}
	if _, err := ts.EnsureSSHKey(); err != nil {
		return nil, false
	}
	pemBytes, err := os.ReadFile(ts.SSHPrivatePath())
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
	return ed25519.Sign(ed, protocol.HandshakeMsg(token, salt)), true
}

// dialAndAuth opens one transport connection and runs the handshake with
// authTok. The caller owns the returned conn on success. A non-nil salt
// means it was carried (and is already replayed-protected) inside a v5
// handshake; nil means the caller writes it as usual (v4 flow).
func (c *Client) dialAndAuth(ctx context.Context, authTok string, timeout time.Duration) (net.Conn, []byte, error) {
	raw, err := c.Transport.Dial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("client: transport dial: %w", err)
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

	salt := protocol.RandomSalt()
	if sig, signed := c.signHandshake(authTok, salt); signed {
		if err := protocol.WriteHandshakeV5(raw, authTok, salt, sig); err != nil {
			raw.Close()
			return nil, nil, fmt.Errorf("client: handshake write: %w", err)
		}
		ver, st, err := protocol.ReadHandshakeStatus(raw)
		if err != nil {
			raw.Close()
			return nil, nil, err
		}
		if ver == protocol.ProtoVersionLegacy && st == protocol.StatusBadVersion {
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
		if ver != protocol.ProtoVersion && ver != protocol.ProtoVersionLegacy {
			raw.Close()
			return nil, nil, protocol.ErrVersionMismatch
		}
		if st != protocol.StatusOK {
			raw.Close()
			return nil, nil, &protocol.AuthError{Status: st}
		}
		return raw, salt, nil
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
	return raw, nil, nil
}

// dialAuthenticated tries each auth candidate on a fresh connection until
// one is accepted; a bad-token rejection falls through to the next candidate.
// Returns the already-sent session salt when the v5 handshake carried it.
func (c *Client) dialAuthenticated(ctx context.Context, timeout time.Duration) (net.Conn, string, []byte, error) {
	candidates := c.authCandidates()
	if len(candidates) == 0 {
		return nil, "", nil, errors.New("client: no auth token available")
	}
	for i, tok := range candidates {
		raw, salt, err := c.dialAndAuth(ctx, tok, timeout)
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
	timeout := c.opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	raw, authTok, salt, err := c.dialAuthenticated(ctx, timeout)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

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
	_ = sec.SetDeadline(time.Time{})
	return sec, nil
}

func (c *Client) getPool() *MuxPool {
	c.poolOnce.Do(func() {
		c.pool = newMuxPool(c.muxSessionFactory, 8, c.opts.DialTimeout)
	})
	return c.pool
}

// DialTunnel returns an AEAD-secured stream connected to target via the
// server. It implements proxy.Dialer.
func (c *Client) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
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
	timeout := c.opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	var rw net.Conn
	if c.opts.Mux {
		stream, err := c.getPool().Open(ctx)
		if err != nil {
			return nil, fmt.Errorf("client: mux open: %w", err)
		}
		rw = stream
	} else {
		raw, err := c.legacyConnect(ctx)
		if err != nil {
			return nil, err
		}
		rw = raw
	}

	_ = rw.SetDeadline(time.Now().Add(timeout))
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
	_ = rw.SetDeadline(time.Time{})
	return rw, nil
}

// legacyConnect runs the v1-style flow: one transport connection per target;
// the ATYP byte of the target request doubles as the implicit mode marker.
func (c *Client) legacyConnect(ctx context.Context) (*protocol.SecureStream, error) {
	timeout := c.opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	raw, authTok, salt, err := c.dialAuthenticated(ctx, timeout)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

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
	return sec, nil
}

// markEverApproved records the durable approval marker for this device
// (fingerprint-keyed), keeping the live token off system-trusted channels
// from this point on — across restarts and re-registrations.
func (c *Client) markEverApproved() {
	store, err := NewTokenStore()
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
	if !c.opts.Mux {
		return nil, fmt.Errorf("client: udp relay requires mux = true")
	}
	stream, err := c.getPool().Open(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write([]byte{protocol.UdpMarker}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("client: udp mode write: %w", err)
	}
	return stream, nil
}
