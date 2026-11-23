package test

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

func TestH3EdgeToH2OriginIsExplicitDuplexAndAuthenticated(t *testing.T) {
	const token = "synthetic-h3-h2-token-123456"
	origin := httptest.NewUnstartedServer(server.Handler(server.Options{Token: token, AllowStreamingHTTP2: true, AllowRestrictedTargets: true}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	cfg := origin.Client().Transport.(*http.Transport).Clone()
	cfg.ForceAttemptHTTP2 = true
	defer cfg.CloseIdleConnections()
	var observedH2 atomic.Bool
	cert := innerTestCert(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	edge := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, origin.URL+protocol.DefaultWSPath, r.Body)
		if err != nil {
			return
		}
		req.Header.Set(protocol.StreamingHeader, r.Header.Get(protocol.StreamingHeader))
		resp, err := cfg.RoundTrip(req)
		if err != nil {
			http.Error(w, "fixture origin unavailable", 502)
			return
		}
		defer resp.Body.Close()
		observedH2.Store(resp.ProtoMajor == 2)
		w.WriteHeader(resp.StatusCode)
		controller := http.NewResponseController(w)
		_ = controller.Flush()
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, err := w.Write(buf[:n]); err != nil {
					return
				}
				_ = controller.Flush()
			}
			if err != nil {
				return
			}
		}
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = edge.Serve(pc) }()
	defer func() { _ = edge.Close(); _ = pc.Close(); <-done }()
	tr := transport.NewH3(transport.H3Options{ServerAddr: pc.LocalAddr().String(), Fingerprint: hex.EncodeToString(transport.FingerprintCert(cert.Certificate[0])), DialTimeout: 2 * time.Second})
	defer tr.(interface{ Close() error }).Close()
	c, err := tr.Dial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteHandshake(c, token); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ReadAuthResponse(c); err != nil {
		t.Fatal("H3/H2 origin handshake", err)
	}
	if !observedH2.Load() {
		t.Fatal("fixture did not use an actual HTTP/2 origin")
	}
	salt := protocol.RandomSalt()
	if err := protocol.WriteSalt(c, salt); err != nil {
		t.Fatal(err)
	}
	secure, err := protocol.ClientSideSecureStream(c, token, salt, protocol.ProfileParams{})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteToken(secure, token); err != nil {
		t.Fatal(err)
	}
	if verdict, err := protocol.ReadToken(secure); err != nil || verdict != "ok" {
		t.Fatal("H3/H2 in-band identity failed", err)
	}
	payload := bytes.Repeat([]byte("h3-h2-duplex-payload"), 4096)
	content := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer content.Close()
	host, port, _ := net.SplitHostPort(content.Listener.Addr().String())
	target, err := parseAddrForTest(host, port)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteTarget(secure, target); err != nil {
		t.Fatal(err)
	}
	if err := protocol.ReadTargetResponse(secure); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(secure, "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n")
	raw, err := io.ReadAll(io.LimitReader(secure, int64(len(payload))+4096))
	if err != nil || !bytes.HasSuffix(raw, payload) {
		t.Fatal("H3 edge/H2 origin authenticated payload did not pass", err)
	}
	noStream := httptest.NewUnstartedServer(server.Handler(server.Options{Token: token}))
	noStream.EnableHTTP2 = true
	noStream.StartTLS()
	defer noStream.Close()
	req, _ := http.NewRequest(http.MethodPost, noStream.URL+protocol.DefaultWSPath, bytes.NewReader([]byte("not-a-tunnel")))
	req.Header.Set(protocol.StreamingHeader, protocol.StreamingValue)
	resp, err := noStream.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") == "application/octet-stream" {
		t.Fatal("H2 streaming enabled without explicit origin consent")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
}
