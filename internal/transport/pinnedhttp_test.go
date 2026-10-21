package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPinnedHTTPClientChromeHelloRoundTrip exercises the control-plane
// client end to end over TLS with the Chrome parrot enabled: status polls
// and health reports ride exactly this path in production.
func TestPinnedHTTPClientChromeHelloRoundTrip(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/token/status" {
			t.Errorf("path %q, want /api/token/status", r.URL.Path)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	cl, err := NewPinnedHTTPClient(PinnedHTTPOptions{
		DialAddr:    srv.Listener.Addr().String(),
		ServerName:  "panel.example",
		Insecure:    true, // test certificate
		ChromeHello: true,
		Timeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	resp, err := cl.Post("https://panel.example/api/token/status", "application/json",
		strings.NewReader(`{"token":"t"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("body %q", body)
	}
}

// TestPinnedHTTPClientRefusesWithoutPin: a non-insecure client with a
// missing or malformed fingerprint must fail to build — never silently
// downgrade to unverified TLS an interceptor could sit beneath.
func TestPinnedHTTPClientRefusesWithoutPin(t *testing.T) {
	if _, err := NewPinnedHTTPClient(PinnedHTTPOptions{DialAddr: "example.com:443", Fingerprint: "zz"}); err == nil {
		t.Fatal("malformed fingerprint must fail the build")
	}
	if _, err := NewPinnedHTTPClient(PinnedHTTPOptions{DialAddr: "example.com:443", Fingerprint: ""}); err == nil {
		t.Fatal("empty fingerprint must fail the build on non-insecure configs")
	}
}
