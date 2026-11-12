package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/streamio"
)

// ServeHTTPProxy uses the standard HTTP parser and framing for absolute-form
// requests. The former raw parser discarded bufio read-ahead, lost POST bodies
// and treated later requests for different hosts as one origin connection.
func ServeHTTPProxy(ctx context.Context, ln net.Listener, d Dialer, logErr *log.Logger) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, authority string) (net.Conn, error) {
			addr, err := authorityToAddr(authority)
			if err != nil {
				return nil, err
			}
			return d.DialTunnel(ctx, addr)
		},
		MaxIdleConns: 64, MaxIdleConnsPerHost: 4, IdleConnTimeout: 60 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	defer tr.CloseIdleConnections()
	srv := &http.Server{
		Handler: httpProxyHandler(ctx, d, tr, logErr), ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx },
		ErrorLog:    logErr,
	}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	if err := srv.Serve(&boundedHTTPListener{Listener: ln, slots: make(chan struct{}, 256)}); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) && logErr != nil {
		logErr.Printf("http-proxy: serve: %v", err)
	}
}

func httpProxyHandler(parent context.Context, d Dialer, tr http.RoundTripper, logErr *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			addr, err := authorityToAddr(r.Host)
			if err != nil || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
				http.Error(w, "invalid CONNECT request", http.StatusBadRequest)
				return
			}
			up, err := d.DialTunnel(r.Context(), addr)
			if err != nil {
				proxyHTTPError(w, addr, err)
				logThrottled(logErr, "connect:"+addr.String(), time.Minute, "http: CONNECT %s: %v", addr, err)
				return
			}
			defer up.Close()
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "CONNECT unavailable", 500)
				return
			}
			conn, buffered, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Time{})
			if _, err := buffered.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
				return
			}
			if err := buffered.Flush(); err != nil {
				return
			}
			// TLS/application bytes may already be buffered after CONNECT.
			// Once hijacked this is a TCP stream, not an HTTP request body.
			// net/http can cancel r.Context on a clean upload-side FIN; that
			// must not discard the response to a half-closed upload.
			Pipe(parent, &bufferedConn{Conn: conn, reader: buffered.Reader}, up)
			return
		}
		if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
			http.Error(w, "absolute http URL required", http.StatusBadRequest)
			return
		}
		addr, err := authorityToAddr(r.URL.Host)
		if r.URL.Port() == "" {
			addr, err = authorityToAddr(net.JoinHostPort(r.URL.Hostname(), "80"))
		}
		if err != nil {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Host = out.URL.Host
		upgrade := r.Header.Get("Upgrade")
		stripProxyHeaders(out.Header)
		if upgrade != "" {
			out.Header.Set("Connection", "Upgrade")
			out.Header.Set("Upgrade", upgrade)
		}
		resp, err := tr.RoundTrip(out)
		if err != nil {
			proxyHTTPError(w, addr, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusSwitchingProtocols {
			rw, ok := resp.Body.(io.ReadWriteCloser)
			if !ok {
				http.Error(w, "unsupported upgrade", 502)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "upgrade unavailable", 500)
				return
			}
			conn, buffered, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Time{})
			if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
				return
			}
			if err := resp.Header.Write(buffered); err != nil {
				return
			}
			if _, err := buffered.WriteString("\r\n"); err != nil {
				return
			}
			if err := buffered.Flush(); err != nil {
				return
			}
			_, _, _ = streamio.Pipe(parent, &bufferedConn{Conn: conn, reader: buffered.Reader}, rw)
			return
		}
		stripProxyHeaders(resp.Header)
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func stripProxyHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(name)
	}
}

func proxyHTTPError(w http.ResponseWriter, addr *protocol.Address, err error) {
	if isBlockedErr(err) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, serveBlockPageHTML(addr, err))
		return
	}
	http.Error(w, "tunnel unavailable", http.StatusBadGateway)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

type boundedHTTPListener struct {
	net.Listener
	slots chan struct{}
}

func (l *boundedHTTPListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedHTTPConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}

type boundedHTTPConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *boundedHTTPConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *boundedHTTPConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
