package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"opentunnel/internal/panelproxy"
	"opentunnel/internal/transport"
)

func testPanelProxyProof(t *testing.T) *panelproxy.Proof {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := panelproxy.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func authenticatedClientIPResult(h *Handler, r *http.Request) (string, int) {
	var ip string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip = clientIP(r)
		w.WriteHeader(http.StatusNoContent)
	})
	w := httptest.NewRecorder()
	h.authenticatePanelProxy(next).ServeHTTP(w, r)
	return ip, w.Code
}

func authenticatedClientIP(h *Handler, r *http.Request) string {
	ip, _ := authenticatedClientIPResult(h, r)
	return ip
}

func TestProxyHeadersRequireLoopbackSourceAndProof(t *testing.T) {
	proof := testPanelProxyProof(t)
	h := New(nil, nil, false).WithProxyProof(proof)
	r := httptest.NewRequest(http.MethodGet, "http://panel.example/", nil)
	r.RemoteAddr = "203.0.113.9:45678"
	if err := proof.Stamp(r, "198.51.100.2", "https", "panel.example"); err != nil {
		t.Fatal(err)
	}
	if got, status := authenticatedClientIPResult(h, r); status != http.StatusForbidden || got != "" {
		t.Fatalf("non-loopback forwarded request was demoted instead of rejected: ip=%q status=%d", got, status)
	}
	r.RemoteAddr = "127.0.0.1:45678"
	if got := authenticatedClientIP(h, r); got != "198.51.100.2" {
		t.Fatalf("genuine stamped loopback request was not honored: %s", got)
	}
	r.Header.Del(panelproxy.ProofHeader)
	if got, status := authenticatedClientIPResult(h, r); status != http.StatusForbidden || got != "" {
		t.Fatalf("unproved relay metadata was demoted instead of rejected: ip=%q status=%d", got, status)
	}
	direct := httptest.NewRequest(http.MethodGet, "http://panel.example/", nil)
	direct.RemoteAddr = "127.0.0.1:45678"
	if got := authenticatedClientIP(h, direct); got != "127.0.0.1" {
		t.Fatalf("header-free direct loopback behavior changed: %s", got)
	}
}

func TestCSRFOriginalHostRequiresProxyProof(t *testing.T) {
	proof := testPanelProxyProof(t)
	h := New(nil, nil, false).WithProxyProof(proof)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := h.authenticatePanelProxy(csrfOriginCheck(next))
	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://panel.example/action", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Origin", "https://attacker.example")
		r.Header.Set(panelproxy.OriginalHostHeader, "attacker.example")
		return r
	}
	for _, test := range []struct {
		name  string
		forge func(*http.Request)
	}{
		{name: "missing proof"},
		{name: "proof does not cover substituted host", forge: func(r *http.Request) {
			_ = proof.Stamp(r, "198.51.100.2", "https", "panel.example")
			r.Header.Set(panelproxy.OriginalHostHeader, "attacker.example")
		}},
		{name: "valid proof from non-loopback peer", forge: func(r *http.Request) {
			_ = proof.Stamp(r, "198.51.100.2", "https", "attacker.example")
			r.RemoteAddr = "203.0.113.9:12345"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := newRequest()
			if test.forge != nil {
				test.forge(r)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("spoofed original-host header bypassed CSRF protection: %d", w.Code)
			}
		})
	}
	genuine := newRequest()
	if err := proof.Stamp(genuine, "198.51.100.2", "https", "attacker.example"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, genuine)
	if w.Code != http.StatusNoContent {
		t.Fatalf("genuine proxy-stamped original host was rejected: %d", w.Code)
	}
}

func TestForgedClientIPDoesNotChangeRateIdentity(t *testing.T) {
	_, h := enrollmentFixture(t, false)
	proof := testPanelProxyProof(t)
	h.WithProxyProof(proof)
	handler := h.Handler()
	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://panel.example/api/token/server-info", nil)
		r.RemoteAddr = "127.0.0.1:45678"
		return r
	}
	forged := newRequest()
	if err := proof.Stamp(forged, "198.51.100.2", "https", "panel.example"); err != nil {
		t.Fatal(err)
	}
	forged.Header.Set(panelproxy.ClientIPHeader, "198.51.100.200")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, forged)
	if w.Code != http.StatusForbidden {
		t.Fatalf("forged relay request was not rejected: %d", w.Code)
	}
	if _, ok := h.rlMap["pool-info|127.0.0.1"]; ok {
		t.Fatal("forged client-IP header mutated the direct loopback rate-limit bucket")
	}
	if _, ok := h.rlMap["pool-info|198.51.100.200"]; ok {
		t.Fatal("forged client-IP header created a separate rate-limit bucket")
	}

	genuine := newRequest()
	if err := proof.Stamp(genuine, "198.51.100.200", "https", "panel.example"); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, genuine)
	if w.Code != http.StatusOK {
		t.Fatalf("genuine capability request failed: %d", w.Code)
	}
	if _, ok := h.rlMap["pool-info|198.51.100.200"]; !ok {
		t.Fatal("valid proxy proof was not used for rate-limit identity")
	}
}

func TestReplayCacheSaturationRejectsWithoutLoopbackDemotion(t *testing.T) {
	_, h := enrollmentFixture(t, false)
	proof := testPanelProxyProof(t)
	h.WithProxyProof(proof)
	handler := h.Handler()
	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://panel.example/api/token/server-info", nil)
		r.RemoteAddr = "127.0.0.1:45678"
		if err := proof.Stamp(r, "198.51.100.200", "https", "panel.example"); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Fill the proof package's bounded 4,096-entry/15-second replay budget.
	// Responses may be 200 or 429; authentication intentionally precedes rate
	// limiting, so every genuine relay nonce is consumed.
	for range 4096 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRequest())
		if w.Code == http.StatusForbidden || w.Code == http.StatusServiceUnavailable {
			t.Fatalf("replay budget failed before expected capacity: %d", w.Code)
		}
	}
	before := len(h.rlMap)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRequest())
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated replay cache status = %d, want 503", w.Code)
	}
	if len(h.rlMap) != before {
		t.Fatal("saturated relay handoff mutated downstream rate-limit state")
	}
	if _, ok := h.rlMap["pool-info|127.0.0.1"]; ok {
		t.Fatal("saturated relay handoff was demoted to direct loopback identity")
	}
}

func TestMissingProxyKeyFailsClosed(t *testing.T) {
	if _, err := panelproxy.New(nil); err == nil {
		t.Fatal("missing TLS private key produced a proxy authenticator")
	}
	missing := filepath.Join(t.TempDir(), "missing-relay-key.pem")
	if _, err := panelproxy.Load(missing, missing); err == nil {
		t.Fatal("missing relay key files produced a proxy authenticator")
	}
	var proof *panelproxy.Proof
	r := httptest.NewRequest(http.MethodGet, "http://panel.example/", nil)
	r.Header.Set(panelproxy.ProofHeader, "forged-proof")
	if err := proof.Stamp(r, "198.51.100.2", "https", "panel.example"); err == nil {
		t.Fatal("nil proof key stamped trusted metadata")
	}
	if r.Header.Get(panelproxy.ProofHeader) != "" {
		t.Fatal("nil proof key left an attacker-supplied proof in place")
	}
	h := New(nil, nil, false)
	r.RemoteAddr = "127.0.0.1:45678"
	if got, status := authenticatedClientIPResult(h, r); status != http.StatusForbidden || got != "" {
		t.Fatalf("missing panel key demoted relay metadata: ip=%q status=%d", got, status)
	}
	direct := httptest.NewRequest(http.MethodGet, "http://panel.example/", nil)
	direct.RemoteAddr = "127.0.0.1:45678"
	if got := authenticatedClientIP(h, direct); got != "127.0.0.1" {
		t.Fatalf("missing panel key changed header-free direct behavior: %s", got)
	}
}

func TestPanelLoadDerivesRelayProcessProof(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "relay-cert.pem")
	keyFile := filepath.Join(dir, "relay-key.pem")
	certificate, _, err := transport.LoadOrCreateCert(certFile, keyFile, "entry.example")
	if err != nil {
		t.Fatal(err)
	}
	relayProof, err := panelproxy.New(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	panelProof, err := panelproxy.Load(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://entry.example/api/token/request", nil)
	if err := relayProof.Stamp(r, "203.0.113.44", "https", "entry.example"); err != nil {
		t.Fatal(err)
	}
	forwarded, ok := panelProof.Verify(r)
	if !ok || forwarded.ClientIP != "203.0.113.44" || forwarded.Scheme != "https" || forwarded.Host != "entry.example" {
		t.Fatal("panel's read-only key load did not derive the relay process proof")
	}
}

func TestAuthenticatedAuthorityForwardingNeedsNoRelayKey(t *testing.T) {
	h := New(nil, nil, false)
	r := httptest.NewRequest(http.MethodPost, "https://authority.example/api/token/request", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set(panelproxy.ClientIPHeader, "198.51.100.77")
	r = panelproxy.MarkAuthority(r)
	if got := authenticatedClientIP(h, r); got != "198.51.100.77" {
		t.Fatalf("authenticated authority forwarding lost client identity: %s", got)
	}
	forwarded, ok := panelproxy.FromRequest(r)
	if !ok || forwarded.Scheme != "https" {
		t.Fatal("authenticated authority forwarding lost its protected scheme")
	}
}

func TestStandaloneConsoleScriptsAreHashAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, httptest.NewRequest("GET", "/admin/sentinel", nil))
	csp := w.Header().Get("Content-Security-Policy")
	scriptPart := strings.Split(strings.Split(csp, "script-src ")[1], ";")[0]
	if strings.Contains(scriptPart, "unsafe-inline") {
		t.Fatal("script policy weakened to unsafe-inline")
	}
	for _, page := range []string{sentinelHTML, killswitchHTML} {
		for _, match := range inlineScripts.FindAllStringSubmatch(page, -1) {
			sum := sha256.Sum256([]byte(match[1]))
			if !strings.Contains(scriptPart, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
				t.Fatal("shipped console script remains blocked by CSP")
			}
		}
	}
}

func TestApprovedKeylessIdentityCannotBeClaimedByBootstrap(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "keyless-approved-token", "approved")
	h := New(db, NewAuth(db), true)
	srv := httptest.NewServer(h.Handler())
	defer srv.Close()
	res := postRegister(t, srv.URL, "keyless-approved-token", "fp", "device", testKeyLine(t))
	if res["http_status"] != "409" || h.SSHKeyPath("keyless-approved-token") != "" {
		t.Fatal("public bootstrap claimed an approved keyless identity")
	}
}

func TestReadOnlyLimitsActionIsReachable(t *testing.T) {
	db := sentinelTestDB(t)
	seedPeer(t, db, "limits-fixture-token", "approved")
	h := New(db, NewAuth(db), false)
	w := httptest.NewRecorder()
	h.apiPeerAction(w, httptest.NewRequest(http.MethodGet, "/admin/api/peers/limits-fixture-token/limits", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "max_bps") {
		t.Fatal("read-only device limits remained behind the POST-only action gate")
	}
}
