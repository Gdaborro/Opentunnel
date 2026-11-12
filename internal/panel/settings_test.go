package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInvalidPolicyBatchDoesNotPartiallyApply(t *testing.T) {
	db := newTestDB(t)
	db.SetSetting("kill_switch_reason", "before")
	h := New(db, NewAuth(db), false)
	rec := httptest.NewRecorder()
	h.apiSettings(rec, httptest.NewRequest(http.MethodPost, "/admin/api/settings", strings.NewReader(`{"kill_switch_reason":"after","ssh_tier_max_bps":-1}`)))
	if rec.Code != 400 || db.Setting("kill_switch_reason") != "before" {
		t.Fatal("invalid batch partially changed policy")
	}
}
func TestSavingDetailsCannotUndoKillSwitch(t *testing.T) {
	db := newTestDB(t)
	db.SetKillSwitch(true)
	h := New(db, NewAuth(db), false)
	rec := httptest.NewRecorder()
	h.apiSettings(rec, httptest.NewRequest(http.MethodPost, "/admin/api/settings", strings.NewReader(`{"kill_switch_reason":"new reason"}`)))
	if rec.Code != 200 || !db.KillSwitch() {
		t.Fatal("detail update changed the independent kill switch")
	}
}
func TestSettingsDatabaseFailureDoesNotReportSuccess(t *testing.T) {
	db := newTestDB(t)
	h := New(db, NewAuth(db), false)
	_ = db.Close()
	rec := httptest.NewRecorder()
	h.apiSettings(rec, httptest.NewRequest(http.MethodPost, "/admin/api/settings", strings.NewReader(`{"kill_switch":true}`)))
	if rec.Code != 503 {
		t.Fatalf("failed database returned %d", rec.Code)
	}
}
