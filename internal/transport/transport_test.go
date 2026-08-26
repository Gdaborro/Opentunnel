package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestWSNetConnEchoThroughPinnedClient verifies the exact client/server
// plumbing this package uses: pinned http.Client -> websocket.Dial ->
// NetConn, against websocket.Accept over TLS.
func TestWSNetConnEchoThroughPinnedClient(t *testing.T) {
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
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"otu1"}})
			if err != nil {
				return
			}
			defer c.Close(websocket.StatusInternalError, "")
			stream := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
			_, _ = io.Copy(stream, stream)
		}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	tr := NewWSTLS(WSTLSOptions{
		ServerAddr:  ln.Addr().String(),
		Fingerprint: fp,
	})
	conn, err := tr.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping-through-tunnel")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
}
