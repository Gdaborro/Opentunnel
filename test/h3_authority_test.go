package test

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

func TestH3LiteralOverrideKeepsTrustedHTTPAuthority(t *testing.T) {
	cert := innerTestCert(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "entry.example:8443" || r.Header.Get("Origin") != "https://entry.example:8443" || r.Header.Get(protocol.StreamingHeader) != protocol.StreamingValue {
			http.Error(w, "authority mismatch", 421)
			return
		}
		w.WriteHeader(http.StatusOK)
		controller := http.NewResponseController(w)
		_ = controller.Flush()
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				_ = controller.Flush()
			}
			if err != nil {
				return
			}
		}
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(pc) }()
	defer func() { _ = server.Close(); _ = pc.Close(); <-done }()
	tr := transport.NewH3(transport.H3Options{ServerAddr: pc.LocalAddr().String(), ServerName: "entry.example", HTTPAuthority: "entry.example:8443", Fingerprint: hex.EncodeToString(transport.FingerprintCert(cert.Certificate[0])), DialTimeout: time.Second})
	defer tr.(interface{ Close() error }).Close()
	c, err := tr.Dial(t.Context())
	if err != nil {
		t.Fatal("H3 dial/name authority separated incorrectly", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("echo")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "echo" {
		t.Fatal("H3 authority transport failed", err)
	}
}
