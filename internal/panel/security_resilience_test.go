package panel

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyHeadersRequireLoopbackSource(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:45678"
	r.Header.Set("X-Otu-Client-IP", "198.51.100.2")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("untrusted proxy header changed caller address: %s", got)
	}
	r.RemoteAddr = "127.0.0.1:45678"
	if got := clientIP(r); got != "198.51.100.2" {
		t.Fatalf("trusted local proxy header was not honored: %s", got)
	}
}

func TestCSRFOriginalHostRequiresTrustedProxy(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r := httptest.NewRequest(http.MethodPost, "https://panel.example/action", nil)
	r.RemoteAddr = "203.0.113.9:12345"
	r.Header.Set("Origin", "https://attacker.example")
	r.Header.Set("X-Otu-Original-Host", "attacker.example")
	w := httptest.NewRecorder()
	csrfOriginCheck(next).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("spoofed original-host header bypassed CSRF protection")
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
