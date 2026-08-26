// Package proxy implements client-side inbound listeners: a local SOCKS5 and
// HTTP proxy that forward application traffic into the tunnel.
package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"

	"opentunnel/internal/protocol"
)

// Dialer produces an authenticated tunnel connection routed to target.
type Dialer interface {
	DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error)
}

// UDPDialer optionally provides the framed UDP relay stream
// (implemented by clients with mux enabled).
type UDPDialer interface {
	OpenUDPRelay(ctx context.Context) (net.Conn, error)
}

const (
	socksVer      = 5
	socksAuthNone = 0x00
	socksCmdConn  = 0x01
	socksCmdUDP   = 0x03
)

// ServeSOCKS5 accepts connections on ln until it closes.
func ServeSOCKS5(ctx context.Context, ln net.Listener, d Dialer, logErr *log.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && logErr != nil {
				logErr.Printf("socks: accept: %v", err)
			}
			return
		}
		go handleSocks(ctx, conn, d, logErr)
	}
}

func handleSocks(ctx context.Context, conn net.Conn, d Dialer, logErr *log.Logger) {
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	// Greeting: VER NMETHODS METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != socksVer {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == socksAuthNone {
			ok = true
			break
		}
	}
	if _, err := conn.Write([]byte{socksVer, map[bool]byte{true: 0x00, false: 0xFF}[ok]}); err != nil || !ok {
		return
	}
	// Request: VER CMD RSV then Address
	req := make([]byte, 3)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != socksVer || req[2] != 0x00 {
		_, _ = conn.Write([]byte{socksVer, 0x01, 0x00})
		return
	}
	switch req[1] {
	case socksCmdConn:
	case socksCmdUDP:
		ud, ok := d.(UDPDialer)
		if !ok {
			_, _ = conn.Write([]byte{socksVer, 0x07, 0x00}) // command not supported
			return
		}
		handleUDPAssociate(ctx, conn, ud, logErr)
		return
	default:
		_, _ = conn.Write([]byte{socksVer, 0x07, 0x00}) // command not supported
		return
	}
	addr, err := protocol.ReadAddress(conn)
	if err != nil {
		return
	}
	// Success reply with wildcard bind address.
	_, _ = conn.Write([]byte{socksVer, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	up, err := d.DialTunnel(ctx, addr)
	if err != nil {
		if logErr != nil {
			logErr.Printf("socks: tunnel %s: %v", addr, err)
		}
		return
	}
	defer up.Close()
	Pipe(ctx, conn, up)
}

// ServeHTTPProxy serves HTTP CONNECT plus absolute-form requests.
func ServeHTTPProxy(ctx context.Context, ln net.Listener, d Dialer, logErr *log.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && logErr != nil {
				logErr.Printf("http-proxy: accept: %v", err)
			}
			return
		}
		go handleHTTPOne(ctx, conn, d, logErr)
	}
}

func handleHTTPOne(ctx context.Context, conn net.Conn, d Dialer, logErr *log.Logger) {
	defer conn.Close()
	req, err := httpReadRequest(conn)
	if err != nil {
		return
	}
	var addr *protocol.Address
	if req.method == httpMethodConnect {
		addr, err = authorityToAddr(req.target)
	} else {
		addr, err = absoluteURLToAddr(req)
	}
	if err != nil {
		httpRespondError(conn, 400, "bad request")
		return
	}
	if req.method == httpMethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		up, err := d.DialTunnel(ctx, addr)
		if err != nil {
			if logErr != nil {
				logErr.Printf("http: tunnel %s: %v", addr, err)
			}
			return
		}
		defer up.Close()
		Pipe(ctx, conn, up)
		return
	}
	// Absolute-form request: rewrite to origin-form and relay raw bytes.
	up, err := d.DialTunnel(ctx, addr)
	if err != nil {
		httpRespondError(conn, 502, "tunnel unavailable")
		return
	}
	defer up.Close()
	line := req.method + " " + req.pathOnly() + " " + req.proto + "\r\n"
	if _, err := io.WriteString(up, line+req.restOfHeaders()); err != nil {
		return
	}
	Pipe(ctx, conn, up)
}
