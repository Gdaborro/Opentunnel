package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"opentunnel/internal/client"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// TestDirectDialTunnel exercises client.DialTunnel without the SOCKS layer.
func TestDirectDialTunnel(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("TARGET HIT from %s", r.RemoteAddr)
		fmt.Fprint(w, "HELLO_FROM_TARGET")
	}))
	defer target.Close()
	tgtHost, tgtPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("target listening on %s:%s", tgtHost, tgtPort)

	cert, fp, err := transport.LoadOrCreateCert("", "", "127.0.0.1")
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
	t.Logf("opentunnel server on %s", srvLn.Addr())

	cl := client.New(transport.NewWSTLS(transport.WSTLSOptions{
		ServerAddr:  srvLn.Addr().String(),
		Fingerprint: fp,
	}), token)

	addr, err := parseAddrForTest(tgtHost, tgtPort)
	if err != nil {
		t.Fatal(err)
	}
	up, err := cl.DialTunnel(context.Background(), addr)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer up.Close()

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", net.JoinHostPort(tgtHost, tgtPort))
	if _, err := up.Write([]byte(req)); err != nil {
		t.Fatalf("write req: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), nil)
	if err != nil {
		t.Fatalf("read resp: %v", err)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	t.Logf("status=%d body=%q", resp.StatusCode, body.String())
	if !bytes.Contains(body.Bytes(), []byte("HELLO_FROM_TARGET")) {
		t.Fatalf("wrong body %q", body.String())
	}
}
