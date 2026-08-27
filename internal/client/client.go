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
	// Per-device token for panel approval (v4) — if we have one, send it
	if perToken := c.perDeviceToken(); perToken != "" {
		if err := protocol.WriteToken(sec, perToken); err != nil {
			sec.Close()
			return nil, fmt.Errorf("client: token write: %w", err)
		}
		if resp, err := protocol.ReadToken(sec); err != nil {
			sec.Close()
			return nil, fmt.Errorf("client: token response: %w", err)
		} else if resp != "ok" {
			sec.Close()
			return nil, fmt.Errorf("client: token %s", resp)
		}
	} else {
		// Legacy: no per-device token yet, skip panel check and proceed
		// Server will handle this as legacy (no token) and create a peer for IP
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
