package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/protocol"
	"opentunnel/internal/proxy"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// startUDPEcho runs a UDP echo service on 127.0.0.1.
func startUDPEcho(t *testing.T) (port int, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
	return atoi(t, p), func() { pc.Close() }
}

func TestUDPRelayThroughTunnel(t *testing.T) {
	echoPort, stopEcho := startUDPEcho(t)
	defer stopEcho()

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

	cl := client.NewWithOptions(transport.NewWSTLS(transport.WSTLSOptions{
		ServerAddr:  srvLn.Addr().String(),
		Fingerprint: fp,
	}), client.Options{Token: token, Mux: true})

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go proxy.ServeSOCKS5(context.Background(), socksLn, cl, nil)
	defer socksLn.Close()

	ctrl, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()

	// SOCKS5 greeting + UDP ASSOCIATE.
	if _, err := ctrl.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	g := make([]byte, 2)
	mustRead(t, ctrl, g)
	if g[1] != 0 {
		t.Fatalf("auth failed: %v", g)
	}
	if _, err := ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	mustRead(t, ctrl, rep)
	if rep[1] != 0 {
		t.Fatalf("associate failed: rep=%v", rep)
	}
	bndPort := int(rep[8])<<8 | int(rep[9])

	udp, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", bndPort))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	dst, err := protocol.ParseAddress("127.0.0.1", echoPort)
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	frame.Write([]byte{0, 0, 0}) // RSV + FRAG=0
	if err := dst.Encode(&frame); err != nil {
		t.Fatal(err)
	}
	frame.WriteString("hello-over-udp")
	if _, err := udp.Write(frame.Bytes()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	_ = udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatalf("no udp reply through tunnel: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("hello-over-udp")) {
		t.Fatalf("unexpected reply %q", buf[:n])
	}
}

func mustRead(t *testing.T, conn net.Conn, buf []byte) {
	t.Helper()
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}

var _ = httptest.NewServer
