package panel

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	diagnosticReadTimeout  = 3 * time.Second
	diagnosticMaxRows      = 16384
	diagnosticMaxJSONBytes = 16 << 20
)

var (
	errDiagnosticUnavailable = errors.New("diagnostic database unavailable")
	errDiagnosticCapacity    = errors.New("diagnostic read capacity exceeded")
	errDiagnosticInvalid     = errors.New("invalid diagnostic value")
)

// readDiagnostic pins all reads in a response to one bounded SQLite snapshot.
// Open configures driver transactions as BEGIN IMMEDIATE for writers; an
// explicit deferred BEGIN here deliberately does not acquire that writer lock.
// Callbacks issue SELECTs only. No policy caches, defaults, or writes are used
// to conceal a failed read, and no partial value escapes on any error.
func readDiagnostic[T any](db *DB, parent context.Context, read func(context.Context, *sql.Conn) (T, error)) (T, error) {
	var zero T
	if db == nil || db.DB == nil {
		return zero, errDiagnosticUnavailable
	}
	ctx, cancel := context.WithTimeout(parent, diagnosticReadTimeout)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return zero, err
	}
	defer conn.Close()
	rollback := true
	defer func() {
		if !rollback {
			return
		}
		// A canceled request must not leave a manually opened transaction on
		// a pooled connection. Discard the connection if cleanup cannot finish.
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := conn.ExecContext(cleanup, "ROLLBACK"); err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		return zero, err
	}
	out, err := read(ctx, conn)
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return zero, err
	}
	if len(raw)+1 > diagnosticMaxJSONBytes {
		return zero, errDiagnosticCapacity
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return zero, err
	}
	rollback = false
	return out, nil
}

// diagnosticRows checks scanning, late iteration/close errors, JSON-safe
// values, and capacity before publishing a list. Full inventories query one
// extra row so capacity exhaustion is unavailable, not silent truncation.
// Recent/top-N feeds retain their existing, intentionally limited windows.
func diagnosticRows[T any](ctx context.Context, conn *sql.Conn, maxRows int, query string, scan func(*sql.Rows) (T, error), args ...any) ([]T, error) {
	rows, err := conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []T{}
	bytes := 0
	for rows.Next() {
		if len(out) >= maxRows {
			return nil, errDiagnosticCapacity
		}
		item, err := scan(rows)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		bytes += len(encoded) + 1
		if bytes > diagnosticMaxJSONBytes {
			return nil, errDiagnosticCapacity
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
}

func diagnosticLimit(limit, fallback int) (int, error) {
	if limit <= 0 {
		limit = fallback
	}
	if limit > diagnosticMaxRows {
		return 0, errDiagnosticCapacity
	}
	return limit, nil
}

func diagnosticCount(ctx context.Context, conn *sql.Conn, query string) (int, error) {
	var n int
	if err := conn.QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, errDiagnosticInvalid
	}
	return n, nil
}

// writeDiagnosticJSON buffers encoding before writing any successful status.
// Neither SQL/scan errors nor corrupt stored values are exposed over HTTP.
func writeDiagnosticJSON(w http.ResponseWriter, value any, readErr error, unavailable string) {
	if readErr != nil {
		http.Error(w, unavailable, http.StatusServiceUnavailable)
		return
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > diagnosticMaxJSONBytes {
		http.Error(w, unavailable, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(raw, '\n'))
}

func (db *DB) PeersChecked(parent context.Context) ([]Peer, error) {
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) ([]Peer, error) {
		return diagnosticRows(ctx, conn, diagnosticMaxRows, `SELECT token, fingerprint, COALESCE(device_name,''), status,
			created_at, last_seen, COALESCE(bytes_up,0), COALESCE(bytes_down,0),
			COALESCE(kick_reason,''), COALESCE(ban_reason,''), COALESCE(last_ip,'')
			FROM peers ORDER BY last_seen DESC LIMIT ?`, func(rows *sql.Rows) (Peer, error) {
			var p Peer
			err := rows.Scan(&p.Token, &p.Fingerprint, &p.DeviceName, &p.Status, &p.CreatedAt, &p.LastSeen,
				&p.BytesUp, &p.BytesDown, &p.KickReason, &p.BanReason, &p.LastIP)
			if err == nil && (p.BytesUp < 0 || p.BytesDown < 0) {
				err = errDiagnosticInvalid
			}
			return p, err
		}, diagnosticMaxRows+1)
	})
}

func (db *DB) StatsChecked(parent context.Context, geo *GeoIP) (map[string]any, error) {
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) (map[string]any, error) {
		var totalUp, totalDown int64
		var active, pending, banned, kicked, expired, total, online, invalid int
		// SQLite SUM otherwise coerces corrupt text counters into zero. NULL
		// counters are optional in released schemas and retain their zero value.
		err := conn.QueryRowContext(ctx, `SELECT COALESCE(SUM(bytes_up),0), COALESCE(SUM(bytes_down),0),
			COUNT(CASE WHEN status='approved' THEN 1 END), COUNT(CASE WHEN status='pending' THEN 1 END),
			COUNT(CASE WHEN status='banned' THEN 1 END), COUNT(CASE WHEN status='kicked' THEN 1 END),
			COUNT(CASE WHEN status='expired' THEN 1 END), COUNT(*),
			COUNT(CASE WHEN last_seen > datetime('now','-5 minutes') THEN 1 END),
			COUNT(CASE WHEN (bytes_up IS NOT NULL AND typeof(bytes_up)!='integer')
				OR (bytes_down IS NOT NULL AND typeof(bytes_down)!='integer')
				OR bytes_up < 0 OR bytes_down < 0 THEN 1 END) FROM peers`).Scan(
			&totalUp, &totalDown, &active, &pending, &banned, &kicked, &expired, &total, &online, &invalid)
		if err != nil {
			return nil, err
		}
		if invalid != 0 || totalUp < 0 || totalDown < 0 || active < 0 || pending < 0 || banned < 0 || kicked < 0 || expired < 0 || total < 0 || online < 0 {
			return nil, errDiagnosticInvalid
		}
		blocked, err := diagnosticCount(ctx, conn, `SELECT COUNT(*) FROM blocklist`)
		if err != nil {
			return nil, err
		}
		var kill string
		if err := conn.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='kill_switch'),'0')`).Scan(&kill); err != nil {
			return nil, err
		}
		countries := map[string]int{}
		if geo != nil {
			ips, err := diagnosticRows(ctx, conn, diagnosticMaxRows,
				`SELECT COALESCE(last_ip,'') FROM peers WHERE status='approved' AND last_ip != '' LIMIT ?`,
				func(rows *sql.Rows) (string, error) {
					var ip string
					err := rows.Scan(&ip)
					return ip, err
				}, diagnosticMaxRows+1)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if name := geo.CountryName(ip); name != "" {
					countries[name]++
				}
			}
		}
		return map[string]any{
			"total_up": totalUp, "total_down": totalDown,
			"active": active, "pending": pending, "banned": banned,
			"kicked": kicked, "expired": expired, "total": total, "blocked": blocked,
			"online": online, "kill_switch": kill != "" && kill != "0", "countries": countries,
		}, nil
	})
}

func (db *DB) WeeklyReportChecked(parent context.Context) ([]map[string]any, error) {
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) ([]map[string]any, error) {
		return diagnosticRows(ctx, conn, 7, `SELECT day, COALESCE(SUM(up),0), COALESCE(SUM(down),0),
			COUNT(CASE WHEN (up IS NOT NULL AND typeof(up)!='integer')
				OR (down IS NOT NULL AND typeof(down)!='integer') OR up < 0 OR down < 0 THEN 1 END)
			FROM daily_usage GROUP BY day ORDER BY day DESC LIMIT 7`, func(rows *sql.Rows) (map[string]any, error) {
			var day string
			var up, down int64
			var invalid int
			if err := rows.Scan(&day, &up, &down, &invalid); err != nil {
				return nil, err
			}
			if invalid != 0 || up < 0 || down < 0 {
				return nil, errDiagnosticInvalid
			}
			return map[string]any{"day": day, "up": up, "down": down}, nil
		})
	})
}

func (db *DB) VisitsChecked(parent context.Context) ([]map[string]any, error) {
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) ([]map[string]any, error) {
		return diagnosticRows(ctx, conn, 100, `SELECT domain, COALESCE(SUM(hits),0), COALESCE(CAST(MAX(last_seen) AS TEXT),''),
			COUNT(CASE WHEN (hits IS NOT NULL AND typeof(hits)!='integer') OR hits < 0 THEN 1 END)
			FROM visits GROUP BY domain ORDER BY SUM(hits) DESC LIMIT 100`, func(rows *sql.Rows) (map[string]any, error) {
			var domain, last string
			var hits int64
			var invalid int
			if err := rows.Scan(&domain, &hits, &last, &invalid); err != nil {
				return nil, err
			}
			if invalid != 0 || hits < 0 {
				return nil, errDiagnosticInvalid
			}
			return map[string]any{"domain": domain, "hits": hits, "last": last}, nil
		})
	})
}

func (db *DB) AbuseChecked(parent context.Context) (map[string]any, error) {
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) (map[string]any, error) {
		var banned, pending, kicked int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(CASE WHEN status='banned' THEN 1 END),
			COUNT(CASE WHEN status='pending' THEN 1 END), COUNT(CASE WHEN status='kicked' THEN 1 END) FROM peers`).Scan(&banned, &pending, &kicked); err != nil {
			return nil, err
		}
		if banned < 0 || pending < 0 || kicked < 0 {
			return nil, errDiagnosticInvalid
		}
		alerts, err := diagnosticCount(ctx, conn, `SELECT COUNT(*) FROM alerts WHERE severity IN ('warning','critical')`)
		if err != nil {
			return nil, err
		}
		return map[string]any{"banned": banned, "pending": pending, "kicked": kicked, "recent_alerts": alerts}, nil
	})
}

func (db *DB) RecentEventsChecked(parent context.Context, limit int) ([]map[string]string, error) {
	limit, err := diagnosticLimit(limit, 30)
	if err != nil {
		return nil, err
	}
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) ([]map[string]string, error) {
		return diagnosticRows(ctx, conn, limit, `SELECT kind, COALESCE(detail,''), at FROM events ORDER BY id DESC LIMIT ?`,
			func(rows *sql.Rows) (map[string]string, error) {
				var kind, detail string
				var at sql.NullString // Preserve the driver's released DATETIME formatting.
				if err := rows.Scan(&kind, &detail, &at); err != nil {
					return nil, err
				}
				return map[string]string{"kind": kind, "detail": detail, "at": at.String}, nil
			}, limit)
	})
}

type diagnosticFinding struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	At       string `json:"at"`
}

func (db *DB) SentinelChecked(parent context.Context) (map[string]any, error) {
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) (map[string]any, error) {
		var mode string
		if err := conn.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='sentinel_mode'),'')`).Scan(&mode); err != nil {
			return nil, err
		}
		mode = strings.TrimSpace(mode)
		if mode == "" {
			mode = "respond" // released default, only after a successful read
		}
		count, err := diagnosticCount(ctx, conn, `SELECT COUNT(*) FROM alerts WHERE kind IN ('sentinel','security') AND at > datetime('now','-1 day')`)
		if err != nil {
			return nil, err
		}
		recent, err := diagnosticRows(ctx, conn, 20,
			`SELECT severity, COALESCE(message,''), at FROM alerts WHERE kind IN ('sentinel','security') ORDER BY id DESC LIMIT 20`,
			func(rows *sql.Rows) (diagnosticFinding, error) {
				var f diagnosticFinding
				var at sql.NullString
				err := rows.Scan(&f.Severity, &f.Message, &at)
				f.At = at.String
				return f, err
			})
		if err != nil {
			return nil, err
		}
		return map[string]any{"mode": mode, "alerts_24h": count, "recent": recent}, nil
	})
}

func (db *DB) AllHealthChecked(parent context.Context) ([]DeviceHealth, error) {
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) ([]DeviceHealth, error) {
		return diagnosticRows(ctx, conn, diagnosticMaxRows, `SELECT p.token, COALESCE(p.device_name,''), p.status,
			COALESCE(h.version,''), COALESCE(h.os,''), COALESCE(h.arch,''),
			COALESCE(h.cpu_pct,0), COALESCE(h.mem_pct,0), COALESCE(h.temp_c,0),
			COALESCE(h.uptime_s,0), COALESCE(h.latency_ms,0), COALESCE(h.jitter_ms,0), COALESCE(h.probe_loss_pct,0),
			COALESCE(p.last_ip,''), COALESCE(h.at,''), COALESCE(h.update_channel,''), COALESCE(h.update_state,''), COALESCE(h.channel_authentication,0)
			FROM peers p LEFT JOIN device_health h ON h.token=p.token ORDER BY p.last_seen DESC LIMIT ?`,
			func(rows *sql.Rows) (DeviceHealth, error) {
				var d DeviceHealth
				err := rows.Scan(&d.Token, &d.DeviceName, &d.Status, &d.Version, &d.OS, &d.Arch,
					&d.CPUPct, &d.MemPct, &d.TempC, &d.UptimeS, &d.LatencyMs, &d.JitterMs, &d.ProbeLossPct,
					&d.LastIP, &d.At, &d.UpdateChannel, &d.UpdateState, &d.ChannelAuthentication)
				return d, err
			}, diagnosticMaxRows+1)
	})
}

func readDiagnosticAlerts(ctx context.Context, conn *sql.Conn, limit int) ([]Alert, error) {
	return diagnosticRows(ctx, conn, limit, `SELECT id, severity, kind, COALESCE(message,''), COALESCE(acked,0), at
		FROM alerts ORDER BY COALESCE(acked,0) ASC, id DESC LIMIT ?`, func(rows *sql.Rows) (Alert, error) {
		var a Alert
		var acked int
		var at sql.NullString
		if err := rows.Scan(&a.ID, &a.Severity, &a.Kind, &a.Message, &acked, &at); err != nil {
			return a, err
		}
		if acked != 0 && acked != 1 {
			return a, errDiagnosticInvalid
		}
		a.Acked = acked == 1
		a.At = at.String
		return a, nil
	}, limit)
}

func readDiagnosticUnackedCount(ctx context.Context, conn *sql.Conn) (int, error) {
	var n, invalid int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(CASE WHEN COALESCE(acked,0)=0 THEN 1 END),
		COUNT(CASE WHEN typeof(COALESCE(acked,0))!='integer' OR COALESCE(acked,0) NOT IN (0,1) THEN 1 END) FROM alerts`).Scan(&n, &invalid); err != nil {
		return 0, err
	}
	if n < 0 || invalid != 0 {
		return 0, errDiagnosticInvalid
	}
	return n, nil
}

func (db *DB) AlertsChecked(parent context.Context, limit int) ([]Alert, error) {
	limit, err := diagnosticLimit(limit, 50)
	if err != nil {
		return nil, err
	}
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) ([]Alert, error) {
		return readDiagnosticAlerts(ctx, conn, limit)
	})
}

func (db *DB) UnackedAlertCountChecked(parent context.Context) (int, error) {
	return readDiagnostic(db, parent, readDiagnosticUnackedCount)
}

func (db *DB) AlertsSnapshotChecked(parent context.Context, limit int) (map[string]any, error) {
	limit, err := diagnosticLimit(limit, 50)
	if err != nil {
		return nil, err
	}
	return readDiagnostic(db, parent, func(ctx context.Context, conn *sql.Conn) (map[string]any, error) {
		alerts, err := readDiagnosticAlerts(ctx, conn, limit)
		if err != nil {
			return nil, err
		}
		unacked, err := readDiagnosticUnackedCount(ctx, conn)
		if err != nil {
			return nil, err
		}
		return map[string]any{"alerts": alerts, "unacked": unacked}, nil
	})
}
