package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestChromeHelloToleratesStrippedALPN pins the MITM reality: a middlebox
// that strips ALPN (or a server offering none) must still complete the
// handshake — we only ever reject a *wrong* non-empty protocol, never an
// absent one.
func TestChromeHelloToleratesStrippedALPN(t *testing.T) {
	certFile := t.TempDir() + "/cert.pem"
	keyFile := t.TempDir() + "/key.pem"
	cert, fp, err := LoadOrCreateCert(certFile, keyFile, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close(websocket.StatusInternalError, "")
			stream := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
			_, _ = io.Copy(stream, stream)
		}),
		// No NextProtos: negotiates nothing, like a stripped ALPN.
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	tr := NewWSTLS(WSTLSOptions{
		ServerAddr:  ln.Addr().String(),
		Fingerprint: fp,
		ChromeHello: true,
	})
	conn, err := tr.Dial(context.Background())
	if err != nil {
		t.Fatalf("stripped ALPN must not break the dial: %v", err)
	}
	defer conn.Close()
	msg := []byte("alpn-strip-probe")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// TestSessionCachesShared asserts the resumption wiring: one shared cache
// object for plain dials (stdlib LRU) and one for Chrome dials (adapter),
// so repeated handshakes can resume instead of paying full cost every time
// sessions churn under rotation windows and TTL quotas.
func TestSessionCachesShared(t *testing.T) {
	if sessionCache == nil {
		t.Fatal("plain session cache must exist")
	}
	if utlsCache == nil {
		t.Fatal("uTLS session cache must exist")
	}
	tr := &wsTLSTransport{opt: WSTLSOptions{Insecure: true}}
	c1, err := tr.tlsConfig("example.com")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := tr.tlsConfig("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c1.ClientSessionCache == nil || c2.ClientSessionCache == nil {
		t.Fatal("tls configs must carry the shared cache")
	}
}
