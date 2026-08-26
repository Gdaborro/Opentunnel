package test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"opentunnel/internal/client"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// countingTransport counts how many underlying transports were dialed so we
// can prove multiplexing reuses one session for many targets.
type countingTransport struct {
	inner transport.Transport
	dials *int
}

func (c *countingTransport) Name() string { return "counting-" + c.inner.Name() }
func (c *countingTransport) Dial(ctx context.Context) (net.Conn, error) {
	*c.dials++
	return c.inner.Dial(ctx)
}

func TestMuxReusesSingleSession(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path)
	}))
	defer target.Close()
	tgtHost, tgtPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := atoi(t, tgtPort)

	tmp := t.TempDir()
	cert, fp, err := transport.LoadOrCreateCert(tmp+"/c.pem", tmp+"/k.pem", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvHTTP := &http.Server{
		Handler:   server.Handler(server.Options{Token: token}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}},
	}
	go func() { _ = srvHTTP.ServeTLS(srvLn, "", "") }()
	defer srvHTTP.Close()

	dials := 0
	real := transport.NewWSTLS(transport.WSTLSOptions{
		ServerAddr:  srvLn.Addr().String(),
		Fingerprint: fp,
	})
	cl := client.NewWithOptions(&countingTransport{inner: real, dials: &dials}, client.Options{
		Token: token,
		Mux:   true,
	})

	const n = 5
	for i := 0; i < n; i++ {
		addr, err := protocol.ParseAddress(tgtHost, port)
		if err != nil {
			t.Fatal(err)
		}
		up, err := cl.DialTunnel(context.Background(), addr)
		if err != nil {
			t.Fatalf("iter %d dial tunnel: %v", i, err)
		}
		req := fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", i, net.JoinHostPort(tgtHost, tgtPort))
		if _, err := io.WriteString(up, req); err != nil {
			t.Fatalf("iter %d write: %v", i, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(up), nil)
		if err != nil {
			t.Fatalf("iter %d response: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		want := fmt.Sprintf("/%d", i)
		if string(body) != want {
			t.Fatalf("iter %d body=%q want=%q", i, body, want)
		}
		up.Close()
	}
	if dials != 1 {
		t.Fatalf("expected exactly 1 transport dial for %d targets, got %d", n, dials)
	}
}
