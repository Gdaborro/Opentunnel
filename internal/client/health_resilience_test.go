package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthLossWindowRecovers(t *testing.T) {
	h := NewHealthReporter(nil, nil, nil)
	for i := 0; i < probeWindow; i++ {
		h.recordProbe(0, errors.New("failed"))
	}
	_, _, loss := h.tunnelStats()
	if loss != 100 {
		t.Fatal("failed probe window did not report complete loss")
	}
	for i := 0; i < probeWindow; i++ {
		h.recordProbe(10*time.Millisecond, nil)
	}
	_, _, loss = h.tunnelStats()
	if loss != 0 {
		t.Fatalf("old failed probes never aged out: loss=%v", loss)
	}
}

func TestHealthLoopHonorsCancellation(t *testing.T) {
	h := NewHealthReporter(nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { h.Run(ctx, time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health worker ignored shutdown")
	}
}

func TestThroughputProbeSupportsHTTPSAndChunkedBodies(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	for _, https := range []bool{false, true} {
		calls := 0
		a, _, _, stop := startAdaptiveFixture(t, ProfileBalanced, &calls, false)
		var sawTLS atomic.Bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawTLS.Store(r.TLS != nil)
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(make([]byte, 1024))
			w.(http.Flusher).Flush() // force chunked framing on HTTP/1.1
			_, _ = w.Write(make([]byte, 4096))
		})
		var target *httptest.Server
		if https {
			target = httptest.NewTLSServer(handler)
		} else {
			target = httptest.NewServer(handler)
		}
		a.ProbeURL, a.ProbeSampleBytes = target.URL, 4096
		if https {
			a.probeTLSConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, bps, err := a.ProbeThroughput(ctx)
		cancel()
		target.Close()
		_ = a.Close()
		stop()
		if err != nil || bps <= 0 || sawTLS.Load() != https {
			t.Fatalf("probe https=%v failed or sent plaintext: %v", https, err)
		}
	}
}
