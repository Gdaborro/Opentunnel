package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusFailureCannotPretendIdentityWasPurged(t *testing.T) {
	for _, code := range []int{403, 429, 500, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", code) }))
			defer s.Close()
			if _, _, _, _, err := fetchStatus(s.Client(), s.URL, "fixture-token-123456", false); err == nil {
				t.Fatal("failure was decoded as missing identity")
			}
		})
	}
}
func TestMalformedStatusCannotTriggerRegistration(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer s.Close()
	if _, _, _, _, err := fetchStatus(s.Client(), s.URL, "fixture-token-123456", false); err == nil {
		t.Fatal("malformed status accepted")
	}
}
