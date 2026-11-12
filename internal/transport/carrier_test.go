package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"opentunnel/internal/protocol"
	localproxy "opentunnel/internal/proxy"
)

type carrierDirectDialer struct{}

func (carrierDirectDialer) DialTunnel(ctx context.Context, a *protocol.Address) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", a.HostPort())
}

func TestExternalCarrierFixedTargetAndLifetime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
		if err != nil {
			return
		}
		defer c.CloseNow()
		rw := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
		_, _ = io.Copy(rw, rw)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go localproxy.ServeSOCKS5(ctx, ln, carrierDirectDialer{}, nil)
	opt := CarrierOptions{SOCKSAddr: ln.Addr().String(), Target: strings.TrimPrefix(srv.URL, "http://"), Path: "/stream", DialTimeout: time.Second}
	c, err := NewCarrier(opt).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("carrier echo")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("carrier echo"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "carrier echo" {
		t.Fatalf("echo=%q error=%v", buf, err)
	}
	cl, err := NewCarrierHTTPClient(opt)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.CloseIdleConnections()
	if resp, err := cl.Get("http://example.invalid/"); err == nil {
		resp.Body.Close()
		t.Fatal("carrier adapter dialed a non-fixed destination")
	}
}
func TestCarrierRejectsPublicOrWildcardEndpoints(t *testing.T) {
	for _, opt := range []CarrierOptions{{SOCKSAddr: "0.0.0.0:19090", Target: "127.0.0.1:8082"}, {SOCKSAddr: "127.0.0.1:19090", Target: "203.0.113.1:8082"}} {
		if _, err := NewCarrierHTTPClient(opt); err == nil {
			t.Fatal("unsafe carrier boundary accepted")
		}
	}
}
