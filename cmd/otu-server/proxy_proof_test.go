package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"opentunnel/internal/panelproxy"
)

func proxyTestKeys(t *testing.T) (*panelproxy.Proof, *panelproxy.Proof) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := panelproxy.New(key)
	if err != nil {
		t.Fatal(err)
	}
	panel, err := panelproxy.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return relay, panel
}

func TestProductionPanelStampUsesExactProxyProof(t *testing.T) {
	proof, panelProof := proxyTestKeys(t)
	r := httptest.NewRequest(http.MethodPost, "https://entry.example/admin/api/login", strings.NewReader("fixture-body"))
	r.RemoteAddr = "203.0.113.44:45678"
	r.Header.Set(panelproxy.ClientIPHeader, "198.51.100.200")
	r.Header.Set(panelproxy.SchemeHeader, "http")
	r.Header.Set(panelproxy.OriginalHostHeader, "attacker.example")
	r.Header.Set(panelproxy.ProofHeader, "forged")
	r.Header.Set("Connection", "X-Otu-Client-IP, X-Otu-Original-Scheme, X-Otu-Original-Host, X-Otu-Proxy-Proof")
	if err := preparePanelProxyRequest(r, false); err != nil {
		t.Fatal(err)
	}
	if got := r.Header.Get(panelproxy.ClientIPHeader); got != "203.0.113.44" {
		t.Fatalf("production stamp retained spoofed client IP: %q", got)
	}
	if got := r.Header.Get(panelproxy.SchemeHeader); got != "https" {
		t.Fatalf("production stamp scheme = %q", got)
	}
	if got := r.Header.Get(panelproxy.OriginalHostHeader); got != "entry.example" {
		t.Fatalf("production stamp host = %q", got)
	}
	if got := r.Header.Get("Connection"); got != "" {
		t.Fatalf("client hop-by-hop header survived sanitization: %q", got)
	}

	target, err := url.Parse("http://127.0.0.1:8090/prefix")
	if err != nil {
		t.Fatal(err)
	}
	out := r.Clone(r.Context())
	director := httputil.NewSingleHostReverseProxy(target).Director
	director(out)
	out.Host = target.Host
	if err := stampPanelProxyRequest(out, proof); err != nil {
		t.Fatal(err)
	}
	if got := len(out.Header.Get(panelproxy.ProofHeader)); got == 0 || got > 128 {
		t.Fatalf("proof is not one bounded value: %d bytes", got)
	}
	forwarded, ok := panelProof.Verify(out)
	if !ok || forwarded.ClientIP != "203.0.113.44" || forwarded.Scheme != "https" || forwarded.Host != "entry.example" {
		t.Fatalf("production headers do not verify as the observed tuple: %+v, %t", forwarded, ok)
	}

	tampered := httptest.NewRequest(http.MethodPost, "https://entry.example/admin/api/login", strings.NewReader("fixture-body"))
	if err := preparePanelProxyRequest(tampered, false); err != nil {
		t.Fatal(err)
	}
	director(tampered)
	tampered.Host = target.Host
	if err := stampPanelProxyRequest(tampered, proof); err != nil {
		t.Fatal(err)
	}
	tampered.Header.Set(panelproxy.SchemeHeader, "http")
	if _, ok := panelProof.Verify(tampered); ok {
		t.Fatal("production proof remained valid after scheme substitution")
	}
}

func TestPanelProxyEndToEndFreshBoundRequests(t *testing.T) {
	relayProof, panelProof := proxyTestKeys(t)
	var hits atomic.Int64
	var captured http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := hits.Add(1)
		authenticated := panelProof.Authenticate(r)
		forwarded, ok := panelproxy.FromRequest(authenticated)
		if !ok {
			http.Error(w, "proof rejected", http.StatusForbidden)
			return
		}
		if forwarded.ClientIP != "203.0.113.44" || forwarded.Scheme != "https" || forwarded.Host != "entry.example" {
			t.Errorf("wrong authenticated metadata: %+v", forwarded)
			http.Error(w, "metadata rejected", http.StatusBadRequest)
			return
		}
		if got := r.URL.RequestURI(); got != "/prefix/admin/api/login?mode=test" {
			t.Errorf("outgoing request target = %q", got)
			http.Error(w, "path rejected", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "fixture-body" {
			t.Errorf("proxied body = %q, %v", body, err)
			http.Error(w, "body rejected", http.StatusBadRequest)
			return
		}
		if hit == 1 {
			captured = r.Header.Clone()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL + "/prefix")
	if err != nil {
		t.Fatal(err)
	}
	handler := newPanelProxy(target, false, relayProof)
	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://entry.example/admin/api/login?mode=test", strings.NewReader("fixture-body"))
		r.RemoteAddr = "203.0.113.44:45678"
		r.Header.Set(panelproxy.ClientIPHeader, "198.51.100.200")
		r.Header.Set(panelproxy.ProofHeader, "forged")
		return r
	}
	for range 2 {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRequest())
		if w.Code != http.StatusNoContent {
			t.Fatalf("fresh genuine request failed: %d: %s", w.Code, w.Body.String())
		}
	}
	if captured == nil {
		t.Fatal("panel did not receive a genuine request")
	}

	replay := httptest.NewRequest(http.MethodPost, upstream.URL+"/prefix/admin/api/login?mode=test", strings.NewReader("fixture-body"))
	for _, name := range []string{panelproxy.ClientIPHeader, panelproxy.SchemeHeader, panelproxy.OriginalHostHeader, panelproxy.ProofHeader} {
		replay.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), captured.Values(name)...)
	}
	w := httptest.NewRecorder()
	upstream.Config.Handler.ServeHTTP(w, replay)
	if w.Code != http.StatusForbidden {
		t.Fatalf("captured proof replayed successfully: %d", w.Code)
	}
}

func TestPanelProxyRejectsFailedHandoffs(t *testing.T) {
	proof, _ := proxyTestKeys(t)
	for _, test := range []struct {
		name  string
		proof *panelproxy.Proof
		host  string
		body  []byte
		want  int
	}{
		{name: "invalid observed host", proof: proof, host: strings.Repeat("a", 1025), want: http.StatusBadRequest},
		{name: "body exceeds proof bound", proof: proof, host: "entry.example", body: make([]byte, panelproxy.MaxBodyBytes+1), want: http.StatusRequestEntityTooLarge},
		{name: "proof unavailable", host: "entry.example", want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			target, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://entry.example/admin/api/login", bytes.NewReader(test.body))
			r.Host = test.host
			w := httptest.NewRecorder()
			newPanelProxy(target, false, test.proof).ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, test.want, w.Body.String())
			}
			if hits.Load() != 0 {
				t.Fatal("failed handoff reached the panel and could use direct loopback identity")
			}
		})
	}
}
