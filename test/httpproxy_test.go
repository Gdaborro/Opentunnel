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
	"opentunnel/internal/proxy"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// TestHTTPProxyAbsoluteFormThroughTunnel covers the plain-HTTP path: an
// absolute-form GET through the local HTTP proxy must be rewritten to
// origin-form and relayed via the tunnel to a real target.
func TestHTTPProxyAbsoluteFormThroughTunnel(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("TARGET HIT: %s %s", r.Method, r.URL.Path)
		fmt.Fprint(w, "PLAIN_HTTP_VIA_TUNNEL")
	}))
	defer target.Close()
	tgtHost, tgtPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

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

	cl := client.New(transport.NewWSTLS(transport.WSTLSOptions{
		ServerAddr:  srvLn.Addr().String(),
		Fingerprint: fp,
	}), token)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go proxy.ServeHTTPProxy(context.Background(), httpLn, cl, nil)
	defer httpLn.Close()

	conn, err := net.Dial("tcp", httpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := fmt.Sprintf("GET http://%s:%s/ HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n",
		tgtHost, tgtPort, tgtHost, tgtPort)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "PLAIN_HTTP_VIA_TUNNEL" {
		t.Fatalf("unexpected body %q", body)
	}
}
