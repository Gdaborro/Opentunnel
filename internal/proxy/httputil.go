package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"opentunnel/internal/protocol"
)

const (
	httpMethodConnect = "CONNECT"
)

type rawRequest struct {
	method, target, proto string
	headers               []string // includes final empty line
}

func httpReadRequest(conn net.Conn) (*rawRequest, error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(strings.TrimRight(line, "\r\n"))
	if len(parts) != 3 {
		return nil, fmt.Errorf("proxy: malformed request line")
	}
	req := &rawRequest{method: parts[0], target: parts[1], proto: parts[2]}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		req.headers = append(req.headers, h)
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return req, nil
}

// pathOnly converts an absolute URI to origin-form for relaying upstream.
func (r *rawRequest) pathOnly() string {
	u, err := url.Parse(r.target)
	if err != nil {
		return "/"
	}
	if u.Path == "" {
		return "/" + u.RawQuery
	}
	return u.RequestURI()
}

func (r *rawRequest) restOfHeaders() string {
	var b strings.Builder
	for _, h := range r.headers {
		b.WriteString(h)
	}
	return b.String()
}

func authorityToAddr(authority string) (*protocol.Address, error) {
	if !strings.Contains(authority, ":") {
		authority += ":443"
	}
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return nil, err
	}
	port := 0
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, err
	}
	return protocol.ParseAddress(host, port)
}

func absoluteURLToAddr(r *rawRequest) (*protocol.Address, error) {
	u, err := url.Parse(r.target)
	if err != nil || u.Scheme != "http" {
		return nil, fmt.Errorf("proxy: unsupported scheme in %q", r.target)
	}
	port := 80
	if p := u.Port(); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			return nil, err
		}
	}
	return protocol.ParseAddress(u.Hostname(), port)
}

func httpRespondError(conn net.Conn, code int, msg string) {
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, msg)
}

// Pipe copies both directions until either side closes or ctx is cancelled.
// 256 KiB buffers reduce syscall pressure on high-BDP paths.
func Pipe(ctx context.Context, a, b net.Conn) {
	bufA := make([]byte, 256*1024)
	bufB := make([]byte, 256*1024)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.CopyBuffer(a, b, bufA)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.CopyBuffer(b, a, bufB)
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	// Half-close gracefully; full close is the caller's defer.
	if tc, ok := a.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	if cw, ok := b.(interface{ CloseWrite() error }); ok && ctx.Err() != nil {
		_ = cw.CloseWrite()
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = a.Close()
	_ = b.Close()
}
