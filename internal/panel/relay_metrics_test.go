package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"opentunnel/internal/metrics"
)

func TestPanelUsesRelayHeartbeatNotOwnCounters(t *testing.T) {
	db := newTestDB(t)
	h := New(db, NewAuth(db), false)
	if err := db.RecordRelayMetrics(metrics.Snapshot{Version: "relay-fixture", ActiveSessions: 7, Goroutines: 42}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.apiServerHealth(rec, httptest.NewRequest(http.MethodGet, "/admin/api/server-health", nil))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["active_sessions"] != float64(7) || out["version"] != "relay-fixture" || out["relay_online"] != true {
		t.Fatalf("incorrect relay metrics: %v", out)
	}
	db.Exec(`UPDATE relay_metrics SET at='2000-01-01 00:00:00'`)
	rec = httptest.NewRecorder()
	h.apiServerHealth(rec, httptest.NewRequest(http.MethodGet, "/admin/api/server-health", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["relay_online"] != false {
		t.Fatal("stale heartbeat reported online")
	}
}
