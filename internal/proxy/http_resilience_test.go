package proxy

import (
	"bufio"
	"context"
	"fmt"
	"github.com/coder/websocket"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"opentunnel/internal/protocol"
)

type testDirectDialer struct{}

func (testDirectDialer) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", target.HostPort())
}

func localHTTPProxy(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); ServeHTTPProxy(ctx, ln, testDirectDialer{}, nil) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("HTTP listener did not stop")
		}
	})
	return ln.Addr().String()
}

func TestHTTPProxyPreservesReadAheadPOSTAndQuery(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials leaked to origin")
		}
		_, _ = fmt.Fprintf(w, "%s|%s", r.URL.RequestURI(), body)
	}))
	defer origin.Close()
	c, err := net.Dial("tcp", localHTTPProxy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := "read-ahead-body"
	_, _ = fmt.Fprintf(c, "POST %s?q=1 HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Length: %d\r\nProxy-Authorization: secret-fixture\r\nConnection: close\r\n\r\n%s", origin.URL, len(payload), payload)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "/?q=1|"+payload {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestHTTPProxyPipeliningCanChangeOrigins(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "origin-a") }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "origin-b") }))
	defer b.Close()
	c, err := net.Dial("tcp", localHTTPProxy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(c, "GET %s/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\nGET %s/ HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n", a.URL, b.URL)
	br := bufio.NewReader(c)
	for _, want := range []string{"origin-a", "origin-b"} {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || string(body) != want {
			t.Fatalf("body=%q want=%q error=%v", body, want, err)
		}
	}
}

func TestCONNECTPreservesPipelinedBytesAndHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		body, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("reply:"), body...))
	}()
	raw, err := net.Dial("tcp", localHTTPProxy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	c := raw.(*net.TCPConn)
	_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\npipelined payload", ln.Addr(), ln.Addr())
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	_ = c.CloseWrite()
	reply, err := io.ReadAll(br)
	if err != nil || string(reply) != "reply:pipelined payload" {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
}

func TestHTTPProxyBoundsHeaders(t *testing.T) {
	c, err := net.Dial("tcp", localHTTPProxy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(c, "GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: localhost\r\nX-Flood: %s\r\n\r\n", strings.Repeat("x", 100<<10))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func FuzzHTTPAuthority(f *testing.F) {
	for _, s := range []string{"example.test:443", "127.0.0.1:80", "[::1]:443", "host:80junk", "user@host:443"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1024 {
			return
		}
		_, _ = authorityToAddr(value)
	})
}

func TestHTTPProxyPreservesWebSocketUpgrade(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
		if err != nil {
			return
		}
		defer c.CloseNow()
		rw := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
		_, _ = io.Copy(rw, rw)
	}))
	defer origin.Close()
	proxyURL, _ := url.Parse("http://" + localHTTPProxy(t))
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer cl.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws://"+strings.TrimPrefix(origin.URL, "http://")+"/stream", &websocket.DialOptions{HTTPClient: cl})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageBinary, []byte("upgraded echo")); err != nil {
		t.Fatal(err)
	}
	_, data, err := c.Read(ctx)
	if err != nil || string(data) != "upgraded echo" {
		t.Fatalf("echo=%q error=%v", data, err)
	}
}
