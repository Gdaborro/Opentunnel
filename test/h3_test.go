package test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"opentunnel/internal/client"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// startH3Server runs the relay handler over HTTP/3 on a loopback UDP
// port, mirroring cmd/otu-server's listener wiring.
func startH3Server(t *testing.T) (addr, fp string) {
	t.Helper()
	tmp := t.TempDir()
	cert, certFP, err := transport.LoadOrCreateCert(tmp+"/c.pem", tmp+"/k.pem", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	h3TLS := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h3"},
	}
	h3srv := &http3.Server{
		TLSConfig: h3TLS,
		Handler:   server.Handler(server.Options{Token: token, AllowRestrictedTargets: true}),
	}
	go func() { _ = h3srv.Serve(udpConn) }()
	t.Cleanup(func() {
		_ = h3srv.Close()
		_ = udpConn.Close()
	})
	return udpConn.LocalAddr().String(), certFP
}

// TestH3TunnelRoundTrip proves the HTTP/3 tier end to end: the pinned
// handshake inside QUIC, the full AEAD/mux protocol stack over the
// streaming request pipe, and a real target relayed through it.
func TestH3TunnelRoundTrip(t *testing.T) {
	addr, fp := startH3Server(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path)
	}))
	defer target.Close()
	tgtHost, tgtPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	h3 := transport.NewH3(transport.H3Options{
		ServerAddr:  addr,
		Fingerprint: fp,
		Path:        protocol.DefaultWSPath,
	})
	cl := client.NewWithOptions(h3, client.Options{
		Token:       token,
		Mux:         true,
		DialTimeout: 10 * time.Second,
	})

	for i := 0; i < 3; i++ {
		taddr, err := protocol.ParseAddress(tgtHost, atoi(t, tgtPort))
		if err != nil {
			t.Fatal(err)
		}
		up, err := cl.DialTunnel(t.Context(), taddr)
		if err != nil {
			t.Fatalf("iter %d dial tunnel over h3: %v", i, err)
		}
		req := fmt.Sprintf("GET /h3-%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", i, net.JoinHostPort(tgtHost, tgtPort))
		if _, err := io.WriteString(up, req); err != nil {
			t.Fatalf("iter %d write: %v", i, err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(up), nil)
		if err != nil {
			t.Fatalf("iter %d response: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		want := fmt.Sprintf("/h3-%d", i)
		if string(body) != want {
			t.Fatalf("iter %d body=%q want %q", i, body, want)
		}
		up.Close()
	}
}

// TestH3LadderOrder pins the escalation sequence: h3 sits between the
// ws-tls profiles and the ssh last resort.
func TestH3LadderOrder(t *testing.T) {
	a := client.NewAdaptive("tok", transport.WSTLSOptions{}, "auto", time.Second)
	if got := a.Current(); got != "fast" {
		t.Fatalf("start tier = %q", got)
	}
	var order []string
	a.EnableH3(func() transport.Transport {
		order = append(order, "h3")
		return transport.NewH3(transport.H3Options{ServerAddr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond})
	})
	a.EnableSSHFallback(func() transport.Transport {
		order = append(order, "ssh")
		// A real (dead) transport: returning nil would panic the client
		// when the factory hands it over.
		return transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond})
	})
	// No live server: every dial fails, but the factories must be visited
	// in ladder order (h3 before ssh).
	_, _ = a.DialTunnel(t.Context(), mustParse(t, "example.org", 443))
	if len(order) < 2 || order[0] != "h3" || order[1] != "ssh" {
		t.Fatalf("escalation order = %v, want h3 before ssh", order)
	}
}

func mustParse(t *testing.T, host string, port int) *protocol.Address {
	t.Helper()
	a, err := protocol.ParseAddress(host, port)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
