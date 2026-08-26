// Package test contains the end-to-end integration test: local SOCKS5 client
// listener -> ws-tls tunnel -> opentunnel server -> local HTTP target.
package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"opentunnel/internal/client"
	"opentunnel/internal/proxy"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

const token = "integration-test-token-1234"

func TestFullChainSOCKS5ThroughTunnel(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("TARGET HIT: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		fmt.Fprint(w, "HELLO_FROM_TARGET")
	}))
	defer target.Close()

	tgtHost, tgtPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, portErr := fmt.Sscanf(tgtPort, "%d", new(int)); portErr != nil {
		t.Fatal(portErr)
	}

	tmp := t.TempDir()
	cert, fp, err := transport.LoadOrCreateCert(tmp+"/cert.pem", tmp+"/key.pem", "127.0.0.1")
	if err != nil {
		t.Fatalf("cert: %v", err)
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
	srvAddr := srvLn.Addr().String()

	cl := client.New(transport.NewWSTLS(transport.WSTLSOptions{
		ServerAddr:  srvAddr,
		Fingerprint: fp,
		Insecure:    false,
	}), token)

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go proxy.ServeSOCKS5(context.Background(), socksLn, cl, log.Default())
	defer socksLn.Close()

	conn, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SOCKS5 greeting (no auth).
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err := readFull(conn, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		t.Fatalf("bad greeting reply: %v", greeting)
	}

	// CONNECT request to target.
	req := []byte{5, 1, 0}
	hostBytes := []byte(tgtHost)
	req = append(req, 3, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	portVal := atoi(t, tgtPort)
	req = append(req, byte(portVal>>8), byte(portVal&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := readFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("socks connect failed, reply=%v", reply)
	}

	// Plain HTTP over the tunnel.
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", tgtHost, tgtPort)
	if _, err := fmt.Fprint(conn, httpReq); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response through tunnel: %v", err)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	if !bytes.Contains(body.Bytes(), []byte("HELLO_FROM_TARGET")) {
		t.Fatalf("unexpected body through tunnel: %q", body.String())
	}
}

func TestDecoyServesNonTunnelRequests(t *testing.T) {
	tmp := t.TempDir()
	cert, _, err := transport.LoadOrCreateCert(tmp+"/cert.pem", tmp+"/key.pem", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:   server.Handler(server.Options{Token: token}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}},
	}
	go func() { _ = srv.ServeTLS(srvLn, "", "") }()
	defer srv.Close()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &http.Client{Transport: tr}
	resp, err := cli.Get("https://" + srvLn.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	if !bytes.Contains(buf.Bytes(), []byte("<!doctype html>")) {
		t.Fatalf("decoy page not served: %q", buf.String())
	}
}

func atoi(t *testing.T, s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("non-numeric port %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
