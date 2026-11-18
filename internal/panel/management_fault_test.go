package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCategoryMalformedMutationCannotDisableExistingProtection(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetCategoryEnabledChecked(t.Context(), "ads", true); err != nil {
		t.Fatal(err)
	}
	h := New(db, NewAuth(db), false)
	for _, body := range []string{
		`{"category":"ads"}`, `{"category":"ads","enabled":null}`,
		`{"category":"ads","enabled":false,"enabled":true}`,
		`{"category":"ads","Enabled":false}`, `{"category":"ads","enabled":false} {}`,
		`null`, `{}`, `{"category":"ads","enabled":false,"unexpected":true}`,
	} {
		w := httptest.NewRecorder()
		h.apiCategories(w, httptest.NewRequest(http.MethodPost, "/admin/api/categories", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("malformed category mutation returned %d", w.Code)
		}
		if blocked, _, err := db.CheckBlocked("doubleclick.net"); err != nil || !blocked {
			t.Fatal("malformed category mutation disabled protection", err)
		}
	}
	w := httptest.NewRecorder()
	h.apiCategories(w, httptest.NewRequest(http.MethodPost, "/admin/api/categories", strings.NewReader(`{"category":"ads","enabled":false}`)))
	if w.Code != http.StatusOK {
		t.Fatal("explicit category choice rejected", w.Code)
	}
}

func TestCategoryReadFaultIsUnavailableNotAllDisabled(t *testing.T) {
	for _, fault := range []string{"missing-table", "unknown-category", "invalid-enabled", "unscannable-enabled"} {
		t.Run(fault, func(t *testing.T) {
			db := newTestDB(t)
			var err error
			switch fault {
			case "missing-table":
				_, err = db.Exec(`ALTER TABLE blocked_categories RENAME TO unavailable_categories`)
			case "unknown-category":
				_, err = db.Exec(`INSERT INTO blocked_categories(category,enabled) VALUES('synthetic-unknown',1)`)
			case "invalid-enabled":
				_, err = db.Exec(`UPDATE blocked_categories SET enabled=2 WHERE category='ads'`)
			case "unscannable-enabled":
				_, err = db.Exec(`UPDATE blocked_categories SET enabled='synthetic-invalid' WHERE category='ads'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if items, err := db.CategoriesChecked(t.Context()); err == nil || items != nil {
				t.Fatal("bad category read reported a complete disabled snapshot")
			}
			db.invalidateBlockCache()
			if blocked, _, err := db.CheckBlocked("previously-allowed.example"); err == nil || !blocked {
				t.Fatal("invalid category row failed open at the relay", err)
			}
			w := httptest.NewRecorder()
			New(db, NewAuth(db), false).apiCategories(w, httptest.NewRequest(http.MethodGet, "/admin/api/categories", nil))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatal("bad category read reported success", w.Code)
			}
		})
	}
}

func TestAlertAcknowledgementIsStrictAuditedAndAtomic(t *testing.T) {
	db := newTestDB(t)
	result, err := db.Exec(`INSERT INTO alerts(severity,kind,message) VALUES('warning','security','synthetic alert')`)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil || id != 1 {
		t.Fatal("synthetic alert ID", id, err)
	}
	h := New(db, NewAuth(db), false)
	for _, body := range []string{
		`{"id":1}`, `{"id":1,"ack":false}`, `{"id":1,"ack":null}`,
		`{"id":1,"ack":true,"ack":false}`, `{"ID":1,"ack":true}`,
		`{"id":1,"ack":true} {}`, `null`, `{"id":-1,"ack":true}`,
	} {
		w := httptest.NewRecorder()
		h.apiAlerts(w, httptest.NewRequest(http.MethodPost, "/admin/api/alerts", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatal("malformed alert acknowledgement accepted", w.Code)
		}
	}
	if _, err := db.Exec(`CREATE TRIGGER deny_alert_ack_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'synthetic fault'); END`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.apiAlerts(w, httptest.NewRequest(http.MethodPost, "/admin/api/alerts", strings.NewReader(`{"id":1,"ack":true}`)))
	var acked, events int
	if err := db.QueryRow(`SELECT acked FROM alerts WHERE id=1`).Scan(&acked); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusServiceUnavailable || acked != 0 {
		t.Fatal("audit failure partially acknowledged alert", w.Code, acked)
	}
	if _, err := db.Exec(`DROP TRIGGER deny_alert_ack_audit`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.apiAlerts(w, httptest.NewRequest(http.MethodPost, "/admin/api/alerts", strings.NewReader(`{"id":1,"ack":true}`)))
	if err := db.QueryRow(`SELECT acked FROM alerts WHERE id=1`).Scan(&acked); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind='alert-ack'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || acked != 1 || events != 1 {
		t.Fatal("successful alert acknowledgement missing durable audit", w.Code, acked, events)
	}
	if err := db.AckAlertChecked(t.Context(), 99999); err == nil {
		t.Fatal("missing alert reported acknowledged")
	}
	w = httptest.NewRecorder()
	h.apiAlerts(w, httptest.NewRequest(http.MethodDelete, "/admin/api/alerts", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("unexpected mutation method accepted", w.Code)
	}
}
