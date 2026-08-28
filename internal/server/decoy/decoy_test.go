package decoy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecoyRouting(t *testing.T) {
	h := Handler(nil)
	cases := []struct {
		path   string
		status int
		want   string // substring expected in body
	}{
		{"/", 200, "Aborro Systems"},
		{"/about", 200, "About Aborro Systems"},
		{"/about/", 200, "About Aborro Systems"},
		{"/services", 200, "Services &amp; pricing"},
		{"/contact", 200, "Contact us"},
		{"/status", 200, "All services operational"},
		{"/style.css", 200, "--accent"},
		{"/favicon.ico", 200, "<svg"},
		{"/robots.txt", 200, "User-agent"},
		{"/definitely-not-a-page", 404, "404"},
		{"/wp-admin", 404, "404"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", c.path, nil))
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d", c.path, rec.Code, c.status)
			continue
		}
		if !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: body missing %q", c.path, c.want)
		}
	}
}

func TestDecoyCustomHTML(t *testing.T) {
	h := Handler([]byte("<html>custom</html>"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/anything", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "custom") {
		t.Fatalf("custom decoy override failed: %d %q", rec.Code, rec.Body.String())
	}
}
