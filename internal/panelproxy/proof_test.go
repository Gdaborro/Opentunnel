package panelproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newUnitProof(t *testing.T) *Proof {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func proofRequest(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:45678"
	return r
}

func stampUnitRequest(t *testing.T, proof *Proof, method, target, body string) *http.Request {
	t.Helper()
	r := proofRequest(method, target, body)
	if err := proof.Stamp(r, "203.0.113.44", "https", "entry.example"); err != nil {
		t.Fatal(err)
	}
	return r
}

func copyUnitProof(dst, src *http.Request) {
	for _, name := range []string{ClientIPHeader, SchemeHeader, OriginalHostHeader, ProofHeader} {
		dst.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), src.Header.Values(name)...)
	}
}

type advancingBody struct {
	read    bool
	advance func()
}

func (b *advancingBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	p[0] = 'x'
	b.advance()
	return 1, nil
}

func (b *advancingBody) Close() error { return nil }

func TestProofFreshSingleUseAndExactTransplant(t *testing.T) {
	proof := newUnitProof(t)
	first := stampUnitRequest(t, proof, http.MethodPost, "https://entry.example/admin/api/login?mode=test", "fixture-body")
	second := stampUnitRequest(t, proof, http.MethodPost, "https://entry.example/admin/api/login?mode=test", "fixture-body")
	if first.Header.Get(ProofHeader) == second.Header.Get(ProofHeader) {
		t.Fatal("identical requests received deterministic proofs")
	}
	if _, ok := proof.Verify(first); !ok {
		t.Fatal("fresh genuine proof was rejected")
	}
	if _, ok := proof.Verify(first); ok {
		t.Fatal("genuine proof was accepted twice")
	}

	exact := proofRequest(http.MethodPost, "https://entry.example/admin/api/login?mode=test", "fixture-body")
	copyUnitProof(exact, second)
	if _, ok := proof.Verify(exact); !ok {
		t.Fatal("unchanged first-use forwarding was rejected")
	}
	replay := proofRequest(http.MethodPost, "https://entry.example/admin/api/login?mode=test", "fixture-body")
	copyUnitProof(replay, second)
	if _, ok := proof.Verify(replay); ok {
		t.Fatal("exact header transplant was replayed")
	}
}

func TestProofRejectsRequestTransplant(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "method", mutate: func(r *http.Request) { r.Method = http.MethodGet }},
		{name: "path", mutate: func(r *http.Request) { r.URL.Path = "/admin/api/setup" }},
		{name: "query", mutate: func(r *http.Request) { r.URL.RawQuery = "mode=other" }},
		{name: "body", mutate: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("changed-body"))
			r.ContentLength = int64(len("changed-body"))
		}},
		{name: "client IP", mutate: func(r *http.Request) { r.Header.Set(ClientIPHeader, "198.51.100.200") }},
		{name: "scheme", mutate: func(r *http.Request) { r.Header.Set(SchemeHeader, "http") }},
		{name: "host", mutate: func(r *http.Request) { r.Header.Set(OriginalHostHeader, "attacker.example") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := newUnitProof(t)
			genuine := stampUnitRequest(t, proof, http.MethodPost, "https://entry.example/admin/api/login?mode=test", "fixture-body")
			candidate := proofRequest(http.MethodPost, "https://entry.example/admin/api/login?mode=test", "fixture-body")
			copyUnitProof(candidate, genuine)
			test.mutate(candidate)
			if _, ok := proof.Verify(candidate); ok {
				t.Fatal("request transplant retained authenticated metadata")
			}
		})
	}
}

func TestProofRejectsWrongKeysAndAmbiguousHeaders(t *testing.T) {
	proof := newUnitProof(t)
	wrong := newUnitProof(t)
	r := stampUnitRequest(t, proof, http.MethodGet, "https://entry.example/api/token/server-info", "")
	if _, ok := wrong.Verify(r); ok {
		t.Fatal("wrong key accepted relay proof")
	}
	for _, name := range []string{ClientIPHeader, SchemeHeader, OriginalHostHeader, ProofHeader} {
		t.Run(name, func(t *testing.T) {
			candidate := proofRequest(http.MethodGet, "https://entry.example/api/token/server-info", "")
			copyUnitProof(candidate, r)
			canonical := http.CanonicalHeaderKey(name)
			candidate.Header[canonical] = append(candidate.Header.Values(name), candidate.Header.Get(name))
			if _, ok := proof.Verify(candidate); ok {
				t.Fatal("duplicate single-valued header was accepted")
			}
		})
	}
	for _, malformed := range []string{"", "v1", "v1.invalid", "v2.a.1.b", "v1.%%%%.1.bad", "v1.AAAAAAAAAAAAAAAAAAAAAA.not-a-time.bad"} {
		candidate := proofRequest(http.MethodGet, "https://entry.example/api/token/server-info", "")
		copyUnitProof(candidate, r)
		candidate.Header.Set(ProofHeader, malformed)
		if _, ok := proof.Verify(candidate); ok {
			t.Fatalf("malformed proof %q was accepted", malformed)
		}
	}
}

func TestProofConcurrentSingleUse(t *testing.T) {
	proof := newUnitProof(t)
	genuine := stampUnitRequest(t, proof, http.MethodPost, "https://entry.example/admin/api/login", "fixture-body")
	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			candidate := proofRequest(http.MethodPost, "https://entry.example/admin/api/login", "fixture-body")
			copyUnitProof(candidate, genuine)
			if _, ok := proof.Verify(candidate); ok {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("single-use proof succeeded %d times", successes.Load())
	}
}

func TestProofExpiryRecheckedAfterBodyRead(t *testing.T) {
	proof := newUnitProof(t)
	now := time.Unix(1000, 0)
	proof.now = func() time.Time { return now }
	r := stampUnitRequest(t, proof, http.MethodPost, "https://entry.example/admin/api/login", "x")
	r.Body = &advancingBody{advance: func() { now = now.Add(proofTTL + time.Second) }}
	r.ContentLength = 1
	if _, ok := proof.Verify(r); ok {
		t.Fatal("proof expired during body buffering was accepted with stale time")
	}
}

func TestProofExpiryAndBoundedCacheRecovery(t *testing.T) {
	proof := newUnitProof(t)
	now := time.Unix(1000, 0)
	proof.now = func() time.Time { return now }
	expired := stampUnitRequest(t, proof, http.MethodGet, "https://entry.example/api/token/server-info", "")
	now = now.Add(proofTTL + time.Second)
	if _, ok := proof.Verify(expired); ok {
		t.Fatal("expired proof was accepted")
	}

	now = time.Unix(1000, 0)
	for range maxUsedProofs {
		r := stampUnitRequest(t, proof, http.MethodGet, "https://entry.example/api/token/server-info", "")
		if _, ok := proof.Verify(r); !ok {
			t.Fatal("fresh proof was rejected before cache capacity")
		}
	}
	pressure := stampUnitRequest(t, proof, http.MethodGet, "https://entry.example/api/token/server-info", "")
	if _, ok := proof.Verify(pressure); ok {
		t.Fatal("bounded replay cache admitted new state under pressure")
	}
	now = now.Add(proofTTL + time.Second)
	recovered := stampUnitRequest(t, proof, http.MethodGet, "https://entry.example/api/token/server-info", "")
	if _, ok := proof.Verify(recovered); !ok {
		t.Fatal("expired replay entries did not release bounded capacity")
	}
}

func TestProofBodyBoundRestoresRejectedRequest(t *testing.T) {
	proof := newUnitProof(t)
	body := strings.Repeat("x", int(MaxBodyBytes+1))
	r := proofRequest(http.MethodPost, "https://entry.example/admin/api/ssh-keys", body)
	if err := proof.Stamp(r, "203.0.113.44", "https", "entry.example"); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversized body error = %v", err)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || len(got) != len(body) {
		t.Fatalf("rejected body was not restored: %d bytes, %v", len(got), err)
	}
	var zero Proof
	if err := zero.Stamp(r, "203.0.113.44", "https", "entry.example"); err == nil {
		t.Fatal("zero-value proof stamped metadata")
	}
	if _, ok := zero.Verify(r); ok {
		t.Fatal("zero-value proof authenticated metadata")
	}
}
