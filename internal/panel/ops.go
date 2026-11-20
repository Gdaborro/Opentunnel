package panel

import (
	"context"
	"errors"
	"strings"
	"time"
)

// DeviceHealth is one client-reported telemetry sample (upsert per device).
type DeviceHealth struct {
	UpdateChannel         string  `json:"update_channel,omitempty"`
	UpdateState           string  `json:"update_state,omitempty"`
	ChannelAuthentication bool    `json:"channel_authentication,omitempty"`
	Token                 string  `json:"token"`
	DeviceName            string  `json:"device_name"`
	Status                string  `json:"status"`
	Version               string  `json:"version"`
	OS                    string  `json:"os"`
	Arch                  string  `json:"arch"`
	CPUPct                float64 `json:"cpu_pct"`
	MemPct                float64 `json:"mem_pct"`
	TempC                 float64 `json:"temp_c"`
	UptimeS               int64   `json:"uptime_s"`
	LatencyMs             float64 `json:"latency_ms"`
	JitterMs              float64 `json:"jitter_ms"`
	ProbeLossPct          float64 `json:"probe_loss_pct"`
	LastIP                string  `json:"last_ip,omitempty"`
	Country               string  `json:"country,omitempty"`
	At                    string  `json:"at"`
}

// ApprovedSSHPubKeys returns the stored public key of every approved
// peer (canonical lines; malformed/empty rows skipped). The panel's
// startup reconcile uses it so a dropped authorized_keys line self-heals
// without admin action.
func (db *DB) ApprovedSSHPubKeys() []string {
	if db == nil {
		return nil
	}
	rows, err := db.Query(`SELECT COALESCE(p.ssh_pubkey,'') FROM peers p
		WHERE p.status='approved' AND NOT EXISTS(SELECT 1 FROM fingerprints_banned f WHERE f.fingerprint=p.fingerprint)
		AND NOT EXISTS(SELECT 1 FROM pubkeys_banned k WHERE k.pubkey=p.ssh_pubkey)
		AND (NOT EXISTS(SELECT 1 FROM server_pool_authority) OR (p.approval_required=0 AND EXISTS(
			SELECT 1 FROM server_pool_authority a JOIN peer_enrollments e ON e.pool_id=a.pool_id
			WHERE e.token=p.token AND e.public_key=p.ssh_pubkey
			AND (a.login_required=0 OR EXISTS(SELECT 1 FROM enrollment_accounts u WHERE u.username=e.username)))))`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var pub string
		if rows.Scan(&pub) == nil && strings.TrimSpace(pub) != "" {
			out = append(out, pub)
		}
	}
	return out
}

// SSHPubKey returns the authorized-key-format public key registered for a
// token ("" when none). The relay verifies v5 handshake signatures
// against it.
func (db *DB) SSHPubKey(token string) string {
	if db == nil {
		return ""
	}
	var pub string
	db.QueryRow(`SELECT COALESCE(ssh_pubkey,'') FROM peers WHERE token=?`, token).Scan(&pub)
	return pub
}

// MarkV5 records the first signature-verified v5 session for a token.
// Sticky: it is the per-peer upgrade latch the downgrade gate keys on.
// The WHERE clause keeps it a one-time write per peer (no hot-path cost).
func (db *DB) MarkV5(token string) {
	if db == nil || token == "" {
		return
	}
	db.Exec(`UPDATE peers SET v5_seen=datetime('now') WHERE token=? AND v5_seen IS NULL`, token)
}

// CommitV5 is the checked, generation-bound upgrade latch used by the relay.
// A targeted write failure or concurrent rekey must not report successful v5
// authentication while leaving unsigned legacy downgrade admission available.
func (db *DB) CommitV5(token, generation, publicKey string) error {
	return db.CommitAuthentication(token, generation, publicKey, false)
}

func (db *DB) CommitAuthentication(token, generation, publicKey string, channelBound bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := accessPolicy(ctx, tx, token)
	if err != nil {
		return err
	}
	if p.Generation != generation || p.PublicKey != publicKey || publicKey == "" || (p.Status != "approved" && p.Status != "kicked") {
		return errors.New("authentication identity changed")
	}
	if (p.ChannelSeen || p.ChannelRequired) && !channelBound {
		return errors.New("connection-bound authentication required for this upgraded identity")
	}
	if !p.V5Seen || (channelBound && !p.ChannelVerified) {
		result, err := tx.ExecContext(ctx, `UPDATE peers SET v5_seen=COALESCE(v5_seen,datetime('now')),channel_seen=MAX(channel_seen,?),channel_epoch=CASE WHEN ? THEN ? ELSE channel_epoch END WHERE token=? AND auth_epoch=? AND ssh_pubkey=? AND status IN ('approved','kicked')`, channelBound, channelBound, generation, token, generation, publicKey)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errors.New("authentication upgrade state was not persisted")
		}
	}
	return tx.Commit()
}

// V5Seen reports whether the peer has ever authenticated with a v5
// proof-of-possession handshake.
func (db *DB) V5Seen(token string) bool {
	if db == nil || token == "" {
		return false
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM peers WHERE token=? AND v5_seen IS NOT NULL`, token).Scan(&n)
	return n > 0
}

// KnownPeer reports whether the panel has a row for the token. The
// in-band control channel mirrors the HTTPS 404 contract with it: unknown
// tokens must read as "" so purged devices re-register on every network.
func (db *DB) KnownPeer(token string) bool {
	if db == nil {
		return false
	}
	var one int
	db.QueryRow(`SELECT 1 FROM peers WHERE token=?`, token).Scan(&one)
	return one == 1
}

// BanReason returns the admin's ban reason for a token ("" when the peer
// is not banned or unknown). Feeds the in-band control channel so banned
// devices see the same reason the HTTPS status endpoint reports.
func (db *DB) BanReason(token string) string {
	if db == nil {
		return ""
	}
	var r string
	db.QueryRow(`SELECT COALESCE(ban_reason,'') FROM peers WHERE token=?`, token).Scan(&r)
	return r
}

// TouchPeer bumps last_seen (control-channel equivalent of a heartbeat:
// the in-band status poll keeps the device "recent" in the panel exactly
// like the HTTPS poll used to).
func (db *DB) TouchPeer(token string) {
	if db == nil {
		return
	}
	db.Exec(`UPDATE peers SET last_seen=datetime('now') WHERE token=?`, token)
}

// RecordVisit upserts the (token, domain) visit counter for the
// monitoring page. Domain only, never URLs.
func (db *DB) RecordVisit(token, domain string) {
	if db == nil || token == "" || domain == "" {
		return
	}
	if !db.telemetryAllowed() {
		return
	}
	db.Exec(`INSERT INTO visits(token,domain,hits,last_seen) VALUES(?,?,1,datetime('now'))
		ON CONFLICT(token,domain) DO UPDATE SET hits=hits+1, last_seen=datetime('now')`, token, domain)
}

// RecordHealth upserts a device telemetry sample.
func (db *DB) RecordHealth(token, version, osName, arch string, cpuPct, memPct, tempC float64, uptimeS int64, latencyMs, jitterMs, probeLossPct float64) {
	if !db.telemetryAllowed() {
		cpuPct, memPct, tempC, latencyMs, jitterMs, probeLossPct = 0, 0, 0, 0, 0, 0
		uptimeS = 0
	}
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
// Legacy callers receive nil on unavailable reads; HTTP uses AllHealthChecked.
func (db *DB) AllHealth() []DeviceHealth {
	out, _ := db.AllHealthChecked(context.Background())
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
// Legacy callers receive nil on unavailable reads; HTTP uses a checked snapshot.
func (db *DB) Alerts(limit int) []Alert {
	out, _ := db.AlertsChecked(context.Background(), limit)
	return out
}

// AckAlert marks an alert acknowledged.
func (db *DB) AckAlert(id int64) {
	_ = db.AckAlertChecked(context.Background(), id)
}

func (db *DB) AckAlertChecked(parent context.Context, id int64) error {
	if id < 1 {
		return errors.New("invalid alert")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE alerts SET acked=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return errors.New("alert not found")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('alert-ack','operator acknowledged an alert')`); err != nil {
		return err
	}
	return tx.Commit()
}

// UnackedAlertCount returns the number of unacknowledged alerts, or -1 when
// unavailable. Error-aware callers should use UnackedAlertCountChecked.
func (db *DB) UnackedAlertCount() int {
	n, err := db.UnackedAlertCountChecked(context.Background())
	if err != nil {
		return -1
	}
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
