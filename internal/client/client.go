// Package client drives outbound tunnel connections: it opens the configured
// transport, authenticates, exchanges a session salt, and speaks the inner
// AEAD protocol toward targets. With Mux enabled it multiplexes every target
// over a small pool of warm sessions.
package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

type Options struct {
	Token       string
	DialTimeout time.Duration // per-connection budget for handshake+target
	Profile     string        // fast | balanced | stealth (shaping on our writes)
	Mux         bool          // multiplex targets over pooled sessions
}

type Client struct {
	Transport transport.Transport
	opts      Options

	poolOnce sync.Once
	pool     *MuxPool
	mu       sync.RWMutex
	banInfo  string // last "banned:reason" or "kicked:reason" from token check
}

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
	raw, err := c.Transport.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: transport dial: %w", err)
	}
	timeout := c.opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

	if err := protocol.WriteHandshake(raw, c.opts.Token); err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: handshake write: %w", err)
	}
	if err := protocol.ReadAuthResponse(raw); err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: auth: %w", err)
	}
	salt := protocol.RandomSalt()
	if err := protocol.WriteSalt(raw, salt); err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: salt write: %w", err)
	}
	sec, err := protocol.ClientSideSecureStream(raw, c.opts.Token, salt, protocol.ProfileFor(c.opts.Profile))
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
		c.pool = newMuxPool(c.muxSessionFactory, 3, c.opts.DialTimeout)
	})
	return c.pool
}

// DialTunnel returns an AEAD-secured stream connected to target via the
// server. It implements proxy.Dialer.
func (c *Client) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	// ISP-level ban/kick: if peer is banned/kicked, show block page for any site and schedule 10min kick
	c.mu.RLock()
	ban := c.banInfo
	c.mu.RUnlock()
	if ban != "" {
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
	raw, err := c.Transport.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: transport dial: %w", err)
	}
	timeout := c.opts.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

	if err := protocol.WriteHandshake(raw, c.opts.Token); err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: handshake write: %w", err)
	}
	if err := protocol.ReadAuthResponse(raw); err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: auth: %w", err)
	}
	salt := protocol.RandomSalt()
	if err := protocol.WriteSalt(raw, salt); err != nil {
		raw.Close()
		return nil, fmt.Errorf("client: salt write: %w", err)
	}
	sec, err := protocol.ClientSideSecureStream(raw, c.opts.Token, salt, protocol.ProfileFor(c.opts.Profile))
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
	}
	return sec, nil
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
