package panel

import (
	"strings"
)

// DeviceHealth is one client-reported telemetry sample (upsert per device).
type DeviceHealth struct {
	Token        string  `json:"token"`
	DeviceName   string  `json:"device_name"`
	Status       string  `json:"status"`
	Version      string  `json:"version"`
	OS           string  `json:"os"`
	Arch         string  `json:"arch"`
	CPUPct       float64 `json:"cpu_pct"`
	MemPct       float64 `json:"mem_pct"`
	TempC        float64 `json:"temp_c"`
	UptimeS      int64   `json:"uptime_s"`
	LatencyMs    float64 `json:"latency_ms"`
	JitterMs     float64 `json:"jitter_ms"`
	ProbeLossPct float64 `json:"probe_loss_pct"`
	LastIP       string  `json:"last_ip,omitempty"`
	Country      string  `json:"country,omitempty"`
	At           string  `json:"at"`
}

// RecordHealth upserts a device telemetry sample.
func (db *DB) RecordHealth(token, version, osName, arch string, cpuPct, memPct, tempC float64, uptimeS int64, latencyMs, jitterMs, probeLossPct float64) {
	db.Exec(`INSERT INTO device_health(token,version,os,arch,cpu_pct,mem_pct,temp_c,uptime_s,latency_ms,jitter_ms,probe_loss_pct,at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
		ON CONFLICT(token) DO UPDATE SET
			version=excluded.version, os=excluded.os, arch=excluded.arch,
			cpu_pct=excluded.cpu_pct, mem_pct=excluded.mem_pct, temp_c=excluded.temp_c,
			uptime_s=excluded.uptime_s, latency_ms=excluded.latency_ms,
			jitter_ms=excluded.jitter_ms, probe_loss_pct=excluded.probe_loss_pct, at=excluded.at`,
		token, version, osName, arch, cpuPct, memPct, tempC, uptimeS, latencyMs, jitterMs, probeLossPct)
}

// AllHealth joins telemetry with peers for the device inventory view.
func (db *DB) AllHealth() []DeviceHealth {
	rows, err := db.Query(`SELECT p.token, p.device_name, p.status,
		COALESCE(h.version,''), COALESCE(h.os,''), COALESCE(h.arch,''),
		COALESCE(h.cpu_pct,0), COALESCE(h.mem_pct,0), COALESCE(h.temp_c,0),
		COALESCE(h.uptime_s,0), COALESCE(h.latency_ms,0), COALESCE(h.jitter_ms,0), COALESCE(h.probe_loss_pct,0),
		COALESCE(p.last_ip,''), COALESCE(h.at,'')
		FROM peers p LEFT JOIN device_health h ON h.token=p.token
		ORDER BY p.last_seen DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []DeviceHealth{}
	for rows.Next() {
		var d DeviceHealth
		if rows.Scan(&d.Token, &d.DeviceName, &d.Status, &d.Version, &d.OS, &d.Arch,
			&d.CPUPct, &d.MemPct, &d.TempC, &d.UptimeS, &d.LatencyMs, &d.JitterMs, &d.ProbeLossPct,
			&d.LastIP, &d.At) == nil {
			out = append(out, d)
		}
	}
	return out
}

// Alert is a panel notification (security event, fault, threshold breach).
type Alert struct {
	ID       int64  `json:"id"`
	Severity string `json:"severity"` // info | warning | critical
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	Acked    bool   `json:"acked"`
	At       string `json:"at"`
}

// RecordAlert appends an alert.
func (db *DB) RecordAlert(severity, kind, message string) {
	db.Exec(`INSERT INTO alerts(severity,kind,message,acked,at) VALUES(?,?,?,0,datetime('now'))`, severity, kind, message)
	db.Exec(`DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 500)`)
}

// RecordAlertOnce records only if no unacked alert with the same kind and
// message prefix exists within the last hour (prevents alert storms).
func (db *DB) RecordAlertOnce(severity, kind, message string) {
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE kind=? AND message=? AND acked=0 AND at > datetime('now','-1 hour')`, kind, message).Scan(&n)
	if n == 0 {
		db.RecordAlert(severity, kind, message)
	}
}

// Alerts returns recent alerts, unacked first.
func (db *DB) Alerts(limit int) []Alert {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.Query(`SELECT id, severity, kind, message, acked, at FROM alerts ORDER BY acked ASC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var acked int
		if rows.Scan(&a.ID, &a.Severity, &a.Kind, &a.Message, &acked, &a.At) == nil {
			a.Acked = acked == 1
			out = append(out, a)
		}
	}
	return out
}

// AckAlert marks an alert acknowledged.
func (db *DB) AckAlert(id int64) {
	db.Exec(`UPDATE alerts SET acked=1 WHERE id=?`, id)
}

// UnackedAlertCount returns the number of unacknowledged alerts.
func (db *DB) UnackedAlertCount() int {
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE acked=0`).Scan(&n)
	return n
}

// shortToken trims a token for alert messages.
func shortToken(token string) string {
	if len(token) > 8 {
		return token[:8]
	}
	return token
}

// offlineSweep raises "device offline" alerts for approved devices unseen
// for 24h. Called by the reaper.
func (db *DB) offlineSweep() {
	rows, err := db.Query(`SELECT token, device_name FROM peers WHERE status='approved' AND last_seen < datetime('now','-1 day')`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var token, name string
		if rows.Scan(&token, &name) == nil {
			if name == "" {
				name = shortToken(token)
			}
			db.RecordAlertOnce("warning", "device-offline", "device "+name+" offline for over 24 hours")
		}
	}
}

// quotaAlert raises a quota-exceeded alert (deduped per device per hour).
func (db *DB) quotaAlert(token string) {
	db.RecordAlertOnce("warning", "quota", "device "+shortToken(token)+" exceeded its data quota")
}

// scheduleAlert raises a schedule-violation notice (deduped per device/hour).
func (db *DB) scheduleAlert(token string) {
	db.RecordAlertOnce("info", "schedule", "device "+shortToken(token)+" blocked outside its access schedule")
}

// trimReason keeps alert messages short.
func trimReason(s string) string {
	if len(s) > 80 {
		return strings.TrimSpace(s[:80]) + "…"
	}
	return s
}
