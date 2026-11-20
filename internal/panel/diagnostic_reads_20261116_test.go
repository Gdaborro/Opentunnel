package panel

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type diagnosticEndpoint20261116 struct {
	name        string
	unavailable string
	handler     func(*Handler, http.ResponseWriter, *http.Request)
}

func diagnosticEndpoints20261116() []diagnosticEndpoint20261116 {
	return []diagnosticEndpoint20261116{
		{"peers", "peer inventory unavailable", (*Handler).apiPeers},
		{"stats", "statistics unavailable", (*Handler).apiStats},
		{"report", "traffic report unavailable", (*Handler).apiReport},
		{"visits", "visit summary unavailable", (*Handler).apiVisits},
		{"abuse", "abuse diagnostics unavailable", (*Handler).apiAbuse},
		{"events", "event feed unavailable", (*Handler).apiEvents},
		{"sentinel", "sentinel diagnostics unavailable", (*Handler).apiSentinel},
		{"alerts", "alerts unavailable", (*Handler).apiAlerts},
		{"devices", "device inventory unavailable", (*Handler).apiDevices},
	}
}

func diagnosticFixture20261116(t *testing.T) *DB {
	t.Helper()
	db := newTestDB(t)
	for _, q := range []string{
		`INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen,bytes_up,bytes_down,last_ip)
			VALUES('diagnostic-peer-first','synthetic-fingerprint',NULL,'approved',datetime('now'),datetime('now'),10,20,'192.0.2.1'),
			('diagnostic-peer-second','synthetic-fingerprint',NULL,'pending',datetime('now'),datetime('now','-1 hour'),30,40,'')`,
		`INSERT INTO alerts(id,severity,kind,message,acked,at) VALUES
			(1,'warning','sentinel','synthetic first finding',0,datetime('now')),
			(2,'critical','security','synthetic second finding',0,datetime('now'))`,
		`INSERT INTO events(id,kind,detail) VALUES(1,'synthetic-event','synthetic old detail'),(2,'synthetic-event','synthetic recent detail')`,
		`INSERT INTO daily_usage(token,day,up,down) VALUES('diagnostic-peer-first','2026-11-16',10,20),('diagnostic-peer-second','2026-11-15',30,40)`,
		`INSERT INTO visits(token,domain,hits) VALUES('diagnostic-peer-first','first.example',10),('diagnostic-peer-second','second.example',5)`,
		`INSERT INTO device_health(token,version,cpu_pct) VALUES('diagnostic-peer-second','synthetic-version',12.5)`,
		`INSERT INTO settings(key,value) VALUES('kill_switch','1'),('sentinel_mode','alert')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal("synthetic diagnostic fixture setup failed", err)
		}
	}
	return db
}

func diagnosticRequest20261116(endpoint diagnosticEndpoint20261116, h *Handler, ctx context.Context) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/api/"+endpoint.name, nil).WithContext(ctx)
	endpoint.handler(h, w, r)
	return w
}

func diagnosticAssertUnavailable20261116(t *testing.T, endpoint diagnosticEndpoint20261116, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s diagnostic read returned %d instead of 503", endpoint.name, w.Code)
	}
	if w.Body.String() != endpoint.unavailable+"\n" {
		t.Fatal("diagnostic fault response was not sanitized or included partial data")
	}
}

func TestDiagnosticReadsUnavailableHTTP20261116(t *testing.T) {
	for _, endpoint := range diagnosticEndpoints20261116() {
		for _, fault := range []string{"closed", "nil", "nil-sql", "canceled"} {
			t.Run(endpoint.name+"/"+fault, func(t *testing.T) {
				var db *DB
				ctx := t.Context()
				switch fault {
				case "closed":
					db = diagnosticFixture20261116(t)
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
				case "nil-sql":
					db = &DB{}
				case "canceled":
					db = diagnosticFixture20261116(t)
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, New(db, nil, false), ctx))
			})
		}
	}
}

func TestDiagnosticReadsMissingTablesHTTP20261116(t *testing.T) {
	dependencies := map[string][]string{
		"peers": {"peers"}, "stats": {"peers", "blocklist", "settings"},
		"report": {"daily_usage"}, "visits": {"visits"}, "abuse": {"peers", "alerts"},
		"events": {"events"}, "sentinel": {"settings", "alerts"},
		"alerts": {"alerts"}, "devices": {"peers", "device_health"},
	}
	for _, endpoint := range diagnosticEndpoints20261116() {
		for _, table := range dependencies[endpoint.name] {
			t.Run(endpoint.name+"/"+table, func(t *testing.T) {
				db := diagnosticFixture20261116(t)
				if _, err := db.Exec("ALTER TABLE " + table + " RENAME TO synthetic_unavailable_" + table); err != nil {
					t.Fatal("synthetic table fault setup failed", err)
				}
				diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, New(db, nil, false), t.Context()))
			})
		}
	}
}

func TestDiagnosticReadsCorruptValuesHTTP20261116(t *testing.T) {
	cases := []struct {
		endpoint string
		fault    string
		queries  []string
	}{
		{"peers", "unscannable-counter", []string{`UPDATE peers SET bytes_up='synthetic-invalid-counter' WHERE token='diagnostic-peer-second'`}},
		{"peers", "unscannable-time", []string{`UPDATE peers SET created_at='synthetic-invalid-time' WHERE token='diagnostic-peer-second'`}},
		{"stats", "coerced-counter", []string{`UPDATE peers SET bytes_up='synthetic-invalid-counter' WHERE token='diagnostic-peer-second'`}},
		{"stats", "sum-overflow", []string{`UPDATE peers SET bytes_up=9223372036854775807`}},
		{"report", "coerced-counter", []string{`UPDATE daily_usage SET up='synthetic-invalid-counter' WHERE day='2026-11-15'`}},
		{"report", "sum-overflow", []string{`UPDATE daily_usage SET day='2026-11-16',up=9223372036854775807`}},
		{"visits", "coerced-counter", []string{`UPDATE visits SET hits='synthetic-invalid-counter' WHERE domain='second.example'`}},
		{"visits", "sum-overflow", []string{`UPDATE visits SET domain='first.example',hits=9223372036854775807`}},
		{"alerts", "unscannable-acked", []string{`UPDATE alerts SET acked='synthetic-invalid-flag' WHERE id=1`}},
		{"alerts", "invalid-acked", []string{`UPDATE alerts SET acked=2 WHERE id=1`}},
		{"events", "unscannable-required-field", []string{
			`ALTER TABLE events RENAME TO synthetic_events`,
			`CREATE VIEW events AS SELECT id,CASE WHEN id=1 THEN NULL ELSE kind END AS kind,detail,at FROM synthetic_events`,
		}},
		{"sentinel", "unscannable-required-field", []string{
			`ALTER TABLE alerts RENAME TO synthetic_alerts`,
			`CREATE VIEW alerts AS SELECT id,NULL AS severity,kind,message,acked,at FROM synthetic_alerts`,
		}},
		{"devices", "unscannable-telemetry", []string{`UPDATE device_health SET cpu_pct='synthetic-invalid-metric'`}},
		{"devices", "invalid-authentication-flag", []string{`UPDATE device_health SET channel_authentication=2`}},
	}
	for _, tc := range cases {
		for _, endpoint := range diagnosticEndpoints20261116() {
			if endpoint.name != tc.endpoint {
				continue
			}
			t.Run(tc.endpoint+"/"+tc.fault, func(t *testing.T) {
				db := diagnosticFixture20261116(t)
				for _, query := range tc.queries {
					if _, err := db.Exec(query); err != nil {
						t.Fatal("synthetic value fault setup failed", err)
					}
				}
				diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, New(db, nil, false), t.Context()))
			})
		}
	}
}

func TestDiagnosticReadsAlertCountFaultOutsideFeed20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	if _, err := db.Exec(`WITH RECURSIVE n(i) AS (VALUES(3) UNION ALL SELECT i+1 FROM n WHERE i<65)
		INSERT INTO alerts(id,severity,kind,message,acked) SELECT i,'warning','synthetic','synthetic feed item',0 FROM n`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE alerts SET acked=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if alerts, err := db.AlertsChecked(t.Context(), 60); err != nil || len(alerts) != 60 {
		t.Fatal("synthetic count fault should be outside the recent feed", err)
	}
	if _, err := db.UnackedAlertCountChecked(t.Context()); err == nil {
		t.Fatal("invalid out-of-feed flag produced an all-clear count")
	}
	for _, endpoint := range diagnosticEndpoints20261116() {
		if endpoint.name == "alerts" {
			diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, New(db, nil, false), t.Context()))
		}
	}
}

func TestDiagnosticReadsOptionalFieldsAndGETNoMutation20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	db.SetMaxOpenConns(1)
	for _, query := range []string{
		`UPDATE peers SET device_name=NULL,bytes_up=NULL,bytes_down=NULL,kick_reason=NULL,ban_reason=NULL,last_ip=NULL`,
		`UPDATE alerts SET message=NULL,acked=NULL,at=NULL`,
		`UPDATE events SET detail=NULL,at=NULL`,
		`UPDATE daily_usage SET up=NULL,down=NULL`,
		`UPDATE visits SET hits=NULL,last_seen=NULL`,
		`UPDATE device_health SET version=NULL,os=NULL,arch=NULL,cpu_pct=NULL,mem_pct=NULL,temp_c=NULL,
			uptime_s=NULL,latency_ms=NULL,jitter_ms=NULL,probe_loss_pct=NULL,at=NULL`,
		`DELETE FROM settings WHERE key IN ('kill_switch','sentinel_mode')`,
		`PRAGMA query_only=ON`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal("synthetic optional field setup failed", err)
		}
	}
	var changesBefore, changesAfter int
	if err := db.QueryRow(`SELECT total_changes()`).Scan(&changesBefore); err != nil {
		t.Fatal(err)
	}
	h := New(db, nil, false)
	for _, endpoint := range diagnosticEndpoints20261116() {
		t.Run(endpoint.name, func(t *testing.T) {
			w := diagnosticRequest20261116(endpoint, h, t.Context())
			if w.Code != http.StatusOK {
				t.Fatalf("released nullable fields rejected by %s: status %d", endpoint.name, w.Code)
			}
			var value any
			if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
				t.Fatal("diagnostic success was not complete JSON", err)
			}
			switch endpoint.name {
			case "peers", "devices", "events", "visits", "report":
				if len(value.([]any)) != 2 {
					t.Fatal("released nullable row silently disappeared")
				}
			case "alerts":
				v := value.(map[string]any)
				if len(v["alerts"].([]any)) != 2 || v["unacked"] != float64(2) {
					t.Fatal("nullable alert rows or counts disappeared")
				}
			case "sentinel":
				v := value.(map[string]any)
				if v["mode"] != "respond" || len(v["recent"].([]any)) != 1 {
					t.Fatal("released default or nullable finding was not preserved")
				}
			case "stats":
				v := value.(map[string]any)
				if v["total"] != float64(2) || v["total_up"] != float64(0) || v["kill_switch"] != false {
					t.Fatal("nullable counters or successful missing-setting default not preserved")
				}
			}
		})
	}
	if err := db.QueryRow(`SELECT total_changes()`).Scan(&changesAfter); err != nil {
		t.Fatal(err)
	}
	if changesBefore != changesAfter {
		t.Fatal("GET diagnostics changed stored data")
	}
	var settings, acked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key IN ('kill_switch','sentinel_mode')`).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE acked IS NOT NULL`).Scan(&acked); err != nil {
		t.Fatal(err)
	}
	if settings != 0 || acked != 0 || !db.killAt.IsZero() {
		t.Fatal("GET diagnostics materialized defaults, acknowledged alerts, or changed a policy cache")
	}
}

func TestDiagnosticReadsSuccessfulSnapshots20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	stats, err := db.StatsChecked(t.Context(), nil)
	if err != nil || stats["total_up"] != int64(40) || stats["total_down"] != int64(60) || stats["active"] != 1 || stats["pending"] != 1 || stats["total"] != 2 || stats["kill_switch"] != true {
		t.Fatal("valid statistics changed", err)
	}
	abuse, err := db.AbuseChecked(t.Context())
	if err != nil || abuse["pending"] != 1 || abuse["recent_alerts"] != 2 {
		t.Fatal("valid abuse counters changed", err)
	}
	sentinel, err := db.SentinelChecked(t.Context())
	if err != nil || sentinel["mode"] != "alert" || sentinel["alerts_24h"] != 2 || len(sentinel["recent"].([]diagnosticFinding)) != 1 {
		t.Fatal("valid sentinel counters changed", err)
	}
	alerts, err := db.AlertsSnapshotChecked(t.Context(), 60)
	if err != nil || alerts["unacked"] != 2 || len(alerts["alerts"].([]Alert)) != 2 {
		t.Fatal("valid alert snapshot changed", err)
	}
}

func TestDiagnosticReadsReleasedTimestampFormatting20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	var eventAt, findingAt, alertAt string
	if err := db.QueryRow(`SELECT at FROM events ORDER BY id DESC LIMIT 1`).Scan(&eventAt); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT at FROM alerts WHERE kind='sentinel' LIMIT 1`).Scan(&findingAt); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT at FROM alerts ORDER BY acked ASC,id DESC LIMIT 1`).Scan(&alertAt); err != nil {
		t.Fatal(err)
	}
	events, err := db.RecentEventsChecked(t.Context(), 50)
	if err != nil || events[0]["at"] != eventAt {
		t.Fatal("released event timestamp formatting changed", err)
	}
	sentinel, err := db.SentinelChecked(t.Context())
	if err != nil || sentinel["recent"].([]diagnosticFinding)[0].At != findingAt {
		t.Fatal("released finding timestamp formatting changed", err)
	}
	alerts, err := db.AlertsChecked(t.Context(), 60)
	if err != nil || alerts[0].At != alertAt {
		t.Fatal("released alert timestamp formatting changed", err)
	}
}

func TestDiagnosticReadsEmptyDatabaseIsComplete20261116(t *testing.T) {
	db := newTestDB(t)
	h := New(db, nil, false)
	for _, endpoint := range diagnosticEndpoints20261116() {
		t.Run(endpoint.name, func(t *testing.T) {
			w := diagnosticRequest20261116(endpoint, h, t.Context())
			if w.Code != http.StatusOK || !json.Valid(w.Body.Bytes()) {
				t.Fatal("successful empty read did not return complete JSON", w.Code)
			}
			switch endpoint.name {
			case "peers", "devices", "events", "visits", "report":
				if w.Body.String() != "[]\n" {
					t.Fatal("successful empty list was indistinguishable from unavailable")
				}
			}
		})
	}
}

func TestDiagnosticReadsCapacityHTTP20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	if _, err := db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<=?)
		INSERT INTO peers(token,fingerprint,device_name,status,created_at,last_seen)
		SELECT 'synthetic-capacity-'||i,'synthetic-fingerprint','synthetic device','pending',datetime('now'),datetime('now') FROM n`, diagnosticMaxRows); err != nil {
		t.Fatal("synthetic capacity setup failed", err)
	}
	for _, endpoint := range diagnosticEndpoints20261116() {
		if endpoint.name == "peers" || endpoint.name == "devices" {
			t.Run(endpoint.name, func(t *testing.T) {
				diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, New(db, nil, false), t.Context()))
			})
		}
	}
	if rows, err := db.AlertsChecked(t.Context(), diagnosticMaxRows+1); !errors.Is(err, errDiagnosticCapacity) || rows != nil {
		t.Fatal("oversized alert read did not return explicit capacity error")
	}
	if rows, err := db.RecentEventsChecked(t.Context(), diagnosticMaxRows+1); !errors.Is(err, errDiagnosticCapacity) || rows != nil {
		t.Fatal("oversized event read did not return explicit capacity error")
	}
	for _, endpoint := range diagnosticEndpoints20261116() {
		if endpoint.name != "events" {
			continue
		}
		large := diagnosticFixture20261116(t)
		if _, err := large.Exec(`UPDATE events SET detail=? WHERE id=2`, strings.Repeat("x", diagnosticMaxJSONBytes)); err != nil {
			t.Fatal(err)
		}
		diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, New(large, nil, false), t.Context()))
	}
}

func TestDiagnosticReadsLegacyWrappersDiscardPartial20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	if _, err := db.Exec(`UPDATE device_health SET cpu_pct='synthetic-invalid-metric'`); err != nil {
		t.Fatal(err)
	}
	if db.AllHealth() != nil {
		t.Fatal("legacy health caller received a partial list")
	}
	if _, err := db.Exec(`UPDATE alerts SET acked='synthetic-invalid-flag' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if db.Alerts(60) != nil || db.UnackedAlertCount() != -1 {
		t.Fatal("legacy alert caller received partial alerts or a zero substitute")
	}
	if _, err := db.Exec(`ALTER TABLE events RENAME TO synthetic_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE VIEW events AS SELECT id,CASE WHEN id=1 THEN NULL ELSE kind END AS kind,detail,at FROM synthetic_events`); err != nil {
		t.Fatal(err)
	}
	if db.RecentEvents(50) != nil {
		t.Fatal("legacy event caller received a partial list")
	}
}

func TestDiagnosticReadsPinnedDeferredSnapshot20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	db.SetMaxOpenConns(2)
	values, err := readDiagnostic(db, t.Context(), func(ctx context.Context, conn *sql.Conn) ([2]int, error) {
		var values [2]int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE acked=0`).Scan(&values[0]); err != nil {
			return values, err
		}
		// The other connection must be able to write in WAL mode while this
		// diagnostic snapshot is open: BEGIN IMMEDIATE would block it.
		writer, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if _, err := db.ExecContext(writer, `UPDATE alerts SET acked=1 WHERE id=1`); err != nil {
			return values, err
		}
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE acked=0`).Scan(&values[1]); err != nil {
			return values, err
		}
		return values, nil
	})
	if err != nil || values != [2]int{2, 2} {
		t.Fatal("read snapshot mixed concurrent commits or took a writer lock", err)
	}
	if n, err := db.UnackedAlertCountChecked(t.Context()); err != nil || n != 1 {
		t.Fatal("next read did not see committed change", err)
	}
}

func TestDiagnosticReadsCancellationReleasesSnapshot20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithCancel(t.Context())
	values, err := readDiagnostic(db, ctx, func(ctx context.Context, conn *sql.Conn) ([]int, error) {
		var count int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&count); err != nil {
			return nil, err
		}
		cancel()
		return []int{count}, nil
	})
	if !errors.Is(err, context.Canceled) || values != nil {
		t.Fatal("canceled snapshot exposed partial data")
	}
	if _, err := db.Exec(`UPDATE alerts SET acked=1 WHERE id=1`); err != nil {
		t.Fatal("canceled diagnostic left a transaction on the pooled connection", err)
	}
	if n, err := db.UnackedAlertCountChecked(t.Context()); err != nil || n != 1 {
		t.Fatal("pooled connection unusable after canceled snapshot", err)
	}
}

func TestDiagnosticReadsConnectionWaitHonorsContext20261116(t *testing.T) {
	db := diagnosticFixture20261116(t)
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if rows, err := db.AllHealthChecked(ctx); !errors.Is(err, context.DeadlineExceeded) || rows != nil {
		t.Fatal("connection capacity wait ignored request deadline or exposed data")
	}
	if time.Since(started) > time.Second {
		t.Fatal("diagnostic connection wait was not bounded")
	}
}

// This test-only driver injects errors after one row, after all rows, and on
// count scans. It never touches a real database or global SQL driver registry.
type diagnosticDriver20261116 struct{}

func (diagnosticDriver20261116) Open(string) (driver.Conn, error) {
	return nil, errors.New("test connector required")
}

type diagnosticConnector20261116 struct {
	query func(string) (driver.Rows, error)
	execs []string
}

func (c *diagnosticConnector20261116) Connect(context.Context) (driver.Conn, error) {
	return &diagnosticConn20261116{connector: c}, nil
}

func (c *diagnosticConnector20261116) Driver() driver.Driver { return diagnosticDriver20261116{} }

type diagnosticConn20261116 struct{ connector *diagnosticConnector20261116 }

func (*diagnosticConn20261116) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("test uses context queries only")
}
func (*diagnosticConn20261116) Close() error { return nil }
func (*diagnosticConn20261116) Begin() (driver.Tx, error) {
	return nil, errors.New("driver writer transactions forbidden in diagnostic tests")
}
func (c *diagnosticConn20261116) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.connector.execs = append(c.connector.execs, query)
	switch query {
	case "BEGIN", "COMMIT", "ROLLBACK":
		return driver.RowsAffected(0), nil
	default:
		return nil, errors.New("diagnostic attempted a data or policy write")
	}
}
func (c *diagnosticConn20261116) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.HasPrefix(strings.TrimSpace(query), "SELECT ") {
		return nil, errors.New("diagnostic attempted a non-SELECT query")
	}
	return c.connector.query(query)
}

type diagnosticRows20261116 struct {
	values   [][]driver.Value
	nextErr  error
	closeErr error
	index    int
	columns  int
}

func (r *diagnosticRows20261116) Columns() []string {
	return make([]string, r.columns)
}
func (r *diagnosticRows20261116) Close() error { return r.closeErr }
func (r *diagnosticRows20261116) Next(dest []driver.Value) error {
	if r.index == len(r.values) {
		if r.nextErr != nil {
			return r.nextErr
		}
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

func diagnosticInjectedDB20261116(t *testing.T, query func(string) (driver.Rows, error)) (*DB, *diagnosticConnector20261116) {
	t.Helper()
	connector := &diagnosticConnector20261116{query: query}
	db := &DB{DB: sql.OpenDB(connector)}
	t.Cleanup(func() { _ = db.Close() })
	return db, connector
}

func diagnosticDriverRow20261116(values ...driver.Value) *diagnosticRows20261116 {
	return &diagnosticRows20261116{columns: len(values), values: [][]driver.Value{values}}
}

func TestDiagnosticReadsLateRowsAndCloseErrorsHTTP20261116(t *testing.T) {
	for _, endpoint := range diagnosticEndpoints20261116() {
		if endpoint.name == "stats" || endpoint.name == "abuse" {
			continue // Count scans are tested separately below.
		}
		for _, fault := range []string{"rows-err", "close-err"} {
			t.Run(endpoint.name+"/"+fault, func(t *testing.T) {
				db, connector := diagnosticInjectedDB20261116(t, func(query string) (driver.Rows, error) {
					if strings.Contains(query, "SELECT COALESCE((SELECT value") {
						return diagnosticDriverRow20261116("alert"), nil
					}
					if strings.Contains(query, "COUNT(*)") && !strings.Contains(query, "GROUP BY") {
						return diagnosticDriverRow20261116(int64(1)), nil
					}
					var rows *diagnosticRows20261116
					switch endpoint.name {
					case "peers":
						rows = diagnosticDriverRow20261116("synthetic-peer", "synthetic-fingerprint", "synthetic device", "pending",
							time.Now(), time.Now(), int64(1), int64(2), "", "", "")
					case "devices":
						rows = diagnosticDriverRow20261116("synthetic-peer", "synthetic device", "pending", "", "", "",
							float64(0), float64(0), float64(0), int64(0), float64(0), float64(0), float64(0), "", "", "", "", int64(0))
					case "report":
						rows = diagnosticDriverRow20261116("2026-11-16", int64(1), int64(2), int64(0))
					case "visits":
						rows = diagnosticDriverRow20261116("synthetic.example", int64(1), "", int64(0))
					case "events":
						rows = diagnosticDriverRow20261116("synthetic", "synthetic detail", "")
					case "alerts":
						rows = diagnosticDriverRow20261116(int64(1), "warning", "synthetic", "synthetic finding", int64(0), "")
					case "sentinel":
						rows = diagnosticDriverRow20261116("warning", "synthetic finding", "")
					}
					if fault == "rows-err" {
						rows.nextErr = errors.New("synthetic late read fault")
					} else {
						rows.closeErr = errors.New("synthetic close fault")
					}
					return rows, nil
				})
				diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, New(db, nil, false), t.Context()))
				if len(connector.execs) != 2 || connector.execs[0] != "BEGIN" || connector.execs[1] != "ROLLBACK" {
					t.Fatal("failed GET did not use and release a read-only snapshot")
				}
			})
		}
	}
}

func TestDiagnosticReadsCountAndCountryErrorsHTTP20261116(t *testing.T) {
	for _, name := range []string{"stats", "abuse", "sentinel", "alerts", "stats-country"} {
		for _, endpoint := range diagnosticEndpoints20261116() {
			if endpoint.name != strings.TrimSuffix(name, "-country") {
				continue
			}
			t.Run(name, func(t *testing.T) {
				db, _ := diagnosticInjectedDB20261116(t, func(query string) (driver.Rows, error) {
					switch {
					case strings.Contains(query, "COALESCE(SUM(bytes_up)"):
						if name == "stats" {
							return diagnosticDriverRow20261116(int64(1), int64(2), "synthetic-invalid-count", int64(0), int64(0), int64(0), int64(0), int64(1), int64(0), int64(0)), nil
						}
						return diagnosticDriverRow20261116(int64(1), int64(2), int64(1), int64(0), int64(0), int64(0), int64(0), int64(1), int64(0), int64(0)), nil
					case strings.Contains(query, "FROM blocklist"):
						return diagnosticDriverRow20261116(int64(0)), nil
					case strings.Contains(query, "SELECT COALESCE((SELECT value"):
						return diagnosticDriverRow20261116("0"), nil
					case strings.Contains(query, "COUNT(CASE WHEN status='banned'"):
						return diagnosticDriverRow20261116(int64(0), int64(0), int64(0)), nil
					case strings.Contains(query, "SELECT id, severity"):
						return diagnosticDriverRow20261116(int64(1), "warning", "synthetic", "synthetic finding", int64(0), ""), nil
					case strings.Contains(query, "COUNT(CASE WHEN COALESCE(acked,0)=0"):
						return diagnosticDriverRow20261116("synthetic-invalid-count", int64(0)), nil
					case strings.Contains(query, "SELECT COALESCE(last_ip"):
						rows := diagnosticDriverRow20261116("192.0.2.1")
						rows.nextErr = errors.New("synthetic country read fault")
						return rows, nil
					default:
						return diagnosticDriverRow20261116("synthetic-invalid-count"), nil
					}
				})
				h := New(db, nil, false)
				if name == "stats-country" {
					h.geo = &GeoIP{}
				}
				diagnosticAssertUnavailable20261116(t, endpoint, diagnosticRequest20261116(endpoint, h, t.Context()))
			})
		}
	}
}
