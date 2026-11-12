package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFirstRunAPIAuthDoesNotRedirectIntoHTML(t *testing.T) {
	db := newTestDB(t)
	handler := New(db, NewAuth(db), false).Handler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil))
	if w.Code != http.StatusUnauthorized || w.Header().Get("Location") != "" {
		t.Fatal("unconfigured admin API returned an HTML setup redirect")
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/api/setup-status", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"needs_setup":true`) {
		t.Fatal("explicit bootstrap status unavailable")
	}
}

func TestSetupDatabaseFailureDoesNotOpenBootstrap(t *testing.T) {
	db := newTestDB(t)
	a := NewAuth(db)
	_ = db.Close()
	if a.NeedsSetup() {
		t.Fatal("failed authority enabled unauthenticated setup")
	}
}
func TestAdminPasswordHashErrorsAreNotIgnored(t *testing.T) {
	db := newTestDB(t)
	a := NewAuth(db)
	if err := a.CreateAdmin("fixture", strings.Repeat("x", 73)); err == nil {
		t.Fatal("oversized bcrypt password created an unusable administrator")
	}
}
func TestSessionStoreBoundsAndExpires(t *testing.T) {
	db := newTestDB(t)
	a := NewAuth(db)
	for range 1024 {
		if a.CreateSession("fixture") == "" {
			t.Fatal("unexpected session failure")
		}
	}
	if a.CreateSession("fixture") != "" {
		t.Fatal("session store did not enforce capacity")
	}
}
