package panel

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func Open(path string, purgeAfterDays int) (*DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	wrapped := &DB{db}
	go reaper(wrapped, purgeAfterDays)
	return wrapped, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS admins (
		id INTEGER PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS peers (
		token TEXT PRIMARY KEY,
		fingerprint TEXT NOT NULL,
		device_name TEXT,
		ssh_pubkey TEXT,
		status TEXT NOT NULL CHECK(status IN ('pending','approved','banned','kicked','expired')),
		created_at DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		expires_at DATETIME,
		bytes_up INTEGER DEFAULT 0,
		bytes_down INTEGER DEFAULT 0,
		kick_expires DATETIME,
		kick_reason TEXT,
		ban_reason TEXT,
		ban_duration TEXT
	);
	CREATE TABLE IF NOT EXISTS blocklist (
		domain TEXT PRIMARY KEY,
		reason TEXT
	);
	CREATE TABLE IF NOT EXISTS fingerprints_banned (
		fingerprint TEXT PRIMARY KEY,
		reason TEXT,
		banned_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS pubkeys_banned (
		pubkey TEXT PRIMARY KEY,
		reason TEXT,
		banned_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY,
		kind TEXT NOT NULL,
		detail TEXT,
		at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS visits (
		token TEXT NOT NULL,
		domain TEXT NOT NULL,
		hits INTEGER DEFAULT 1,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY(token, domain)
	);
	CREATE TABLE IF NOT EXISTS daily_usage (
		token TEXT NOT NULL,
		day TEXT NOT NULL,
		up INTEGER DEFAULT 0,
		down INTEGER DEFAULT 0,
		PRIMARY KEY(token, day)
	);
	CREATE INDEX IF NOT EXISTS idx_peers_status ON peers(status);
	CREATE INDEX IF NOT EXISTS idx_peers_fingerprint ON peers(fingerprint);
	CREATE INDEX IF NOT EXISTS idx_visits_domain ON visits(domain);
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT
	);
	CREATE TABLE IF NOT EXISTS blocked_categories (
		category TEXT PRIMARY KEY,
		enabled INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS device_health (
		token TEXT PRIMARY KEY,
		version TEXT, os TEXT, arch TEXT,
		cpu_pct REAL, mem_pct REAL, temp_c REAL,
		uptime_s INTEGER,
		latency_ms REAL, jitter_ms REAL, probe_loss_pct REAL,
		at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY,
		severity TEXT NOT NULL,
		kind TEXT NOT NULL,
		message TEXT,
		acked INTEGER DEFAULT 0,
		at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`)
	if err != nil {
		return err
	}
	// Idempotent column additions (SQLite has no ALTER … IF NOT EXISTS).
	for _, col := range []struct{ name, def string }{
		{"schedule", "TEXT DEFAULT ''"},
		{"max_bps", "INTEGER DEFAULT 0"},
		{"quota_bytes", "INTEGER DEFAULT 0"},
		{"last_ip", "TEXT DEFAULT ''"},
	} {
		var n int
		db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name=?`, col.name).Scan(&n)
		if n == 0 {
			if _, err := db.Exec(`ALTER TABLE peers ADD COLUMN ` + col.name + ` ` + col.def); err != nil {
				return err
			}
		}
	}
	// Seed the built-in categories (disabled until an admin enables them).
	for cat := range categoryLists {
		db.Exec(`INSERT OR IGNORE INTO blocked_categories(category,enabled) VALUES(?,0)`, cat)
	}
	return nil
}

// reaper purges devices that have not connected within purgeAfterDays so
// stale devices must re-register and be re-approved, and releases expired
// kicks. Banned peers are kept (their identities stay blocked).
func reaper(db *DB, purgeAfterDays int) {
	if purgeAfterDays <= 0 {
		purgeAfterDays = 14
	}
	window := fmt.Sprintf("-%d days", purgeAfterDays)
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		db.Exec(`DELETE FROM peers WHERE status IN ('approved','pending','expired','kicked') AND last_seen < datetime('now', ?)`, window)
		db.Exec(`DELETE FROM visits WHERE token NOT IN (SELECT token FROM peers)`)
		db.Exec(`DELETE FROM daily_usage WHERE token NOT IN (SELECT token FROM peers)`)
		db.Exec(`DELETE FROM device_health WHERE token NOT IN (SELECT token FROM peers)`)
		db.Exec(`UPDATE peers SET status='approved', kick_expires=NULL, kick_reason=NULL WHERE status='kicked' AND kick_expires IS NOT NULL AND kick_expires < datetime('now')`)
		db.Exec(`DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)`)
		db.offlineSweep()
	}
}

// RecordEvent appends to the panel event feed (pruned by the reaper).
func (db *DB) RecordEvent(kind, detail string) {
	db.Exec(`INSERT INTO events(kind,detail,at) VALUES(?,?,datetime('now'))`, kind, detail)
}

// RecentEvents returns the newest events for the panel feed.
func (db *DB) RecentEvents(limit int) []map[string]string {
	if limit <= 0 {
		limit = 30
	}
	rows, err := db.Query(`SELECT kind, detail, at FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var k, d, at string
		if rows.Scan(&k, &d, &at) == nil {
			out = append(out, map[string]string{"kind": k, "detail": d, "at": at})
		}
	}
	return out
}

// BanIdentity blocks the peer's fingerprint and device public key so a ban
// cannot be shed by re-registering with a fresh token on the same device.
func (db *DB) BanIdentity(token, reason string) {
	var fp, pub string
	if err := db.QueryRow(`SELECT fingerprint, COALESCE(ssh_pubkey,'') FROM peers WHERE token=?`, token).Scan(&fp, &pub); err != nil {
		return
	}
	if fp != "" {
		db.Exec(`INSERT OR REPLACE INTO fingerprints_banned(fingerprint,reason,banned_at) VALUES(?,?,datetime('now'))`, fp, reason)
	}
	if pub != "" {
		db.Exec(`INSERT OR REPLACE INTO pubkeys_banned(pubkey,reason,banned_at) VALUES(?,?,datetime('now'))`, pub, reason)
	}
}

// UnbanIdentity clears the identity blocks for a peer (fingerprint + key).
func (db *DB) UnbanIdentity(token string) {
	var fp, pub string
	if err := db.QueryRow(`SELECT fingerprint, COALESCE(ssh_pubkey,'') FROM peers WHERE token=?`, token).Scan(&fp, &pub); err != nil {
		return
	}
	if fp != "" {
		db.Exec(`DELETE FROM fingerprints_banned WHERE fingerprint=?`, fp)
	}
	if pub != "" {
		db.Exec(`DELETE FROM pubkeys_banned WHERE pubkey=?`, pub)
	}
}

// IdentityBanned reports whether a fingerprint or device public key is banned.
func (db *DB) IdentityBanned(fingerprint, pubkey string) bool {
	var n int
	if fingerprint != "" {
		db.QueryRow(`SELECT COUNT(*) FROM fingerprints_banned WHERE fingerprint=?`, fingerprint).Scan(&n)
		if n > 0 {
			return true
		}
	}
	if pubkey != "" {
		db.QueryRow(`SELECT COUNT(*) FROM pubkeys_banned WHERE pubkey=?`, pubkey).Scan(&n)
		if n > 0 {
			return true
		}
	}
	return false
}

// identityBanReason returns the stored reason for an identity ban.
func (db *DB) identityBanReason(fingerprint, pubkey string) string {
	var r string
	if fingerprint != "" {
		if db.QueryRow(`SELECT COALESCE(reason,'') FROM fingerprints_banned WHERE fingerprint=?`, fingerprint).Scan(&r) == nil && r != "" {
			return r
		}
	}
	if pubkey != "" {
		if db.QueryRow(`SELECT COALESCE(reason,'') FROM pubkeys_banned WHERE pubkey=?`, pubkey).Scan(&r) == nil && r != "" {
			return r
		}
	}
	return "device identity banned"
}

type Peer struct {
	Token       string     `json:"token"`
	Fingerprint string     `json:"fingerprint"`
	DeviceName  string     `json:"device_name"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeen    time.Time  `json:"last_seen"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	BytesUp     int64      `json:"bytes_up"`
	BytesDown   int64      `json:"bytes_down"`
	KickExpires *time.Time `json:"kick_expires,omitempty"`
	KickReason  string     `json:"kick_reason,omitempty"`
	BanReason   string     `json:"ban_reason,omitempty"`
	BanDuration string     `json:"ban_duration,omitempty"`
	LastIP      string     `json:"last_ip,omitempty"`
	Country     string     `json:"country,omitempty"`
}

func (db *DB) CheckToken(token string) (status, reason, kickExpires string, err error) {
	var s, kr, br, ke, fp, pub, sched string
	var quota, up, down int64
	err = db.QueryRow(`SELECT status, COALESCE(kick_reason,''), COALESCE(ban_reason,''), COALESCE(kick_expires,''), fingerprint, COALESCE(ssh_pubkey,''), COALESCE(schedule,''), COALESCE(quota_bytes,0), COALESCE(bytes_up,0), COALESCE(bytes_down,0) FROM peers WHERE token=?`, token).Scan(&s, &kr, &br, &ke, &fp, &pub, &sched, &quota, &up, &down)
	if err != nil {
		return "pending", "", "", nil
	}
	// Identity bans trump peer status: a banned device stays banned even if
	// its row was manipulated back to approved.
	if db.IdentityBanned(fp, pub) {
		if br == "" {
			br = db.identityBanReason(fp, pub)
		}
		return "banned", br, "", nil
	}
	if s == "banned" {
		return "banned", br, "", nil
	}
	if s == "kicked" {
		// Expired kicks clear inline so devices aren't locked out until the
		// hourly reaper happens to tick.
		if ke != "" {
			if exp, perr := time.Parse("2006-01-02 15:04:05", ke); perr == nil && time.Now().UTC().After(exp) {
				db.Exec(`UPDATE peers SET status='approved', kick_expires=NULL, kick_reason=NULL WHERE token=?`, token)
				s = "approved"
			}
		}
		if s == "kicked" {
			return "kicked", kr, ke, nil
		}
	}
	if s == "pending" || s == "expired" {
		return s, "", "", nil
	}
	// approved — ISP controls: data quota, then access schedule.
	if quota > 0 && up+down >= quota {
		db.quotaAlert(token)
		return "kicked", "data quota exceeded", "", nil
	}
	if !scheduleAllows(sched, time.Now()) {
		db.scheduleAlert(token)
		return "kicked", "outside allowed hours (schedule)", nextScheduleStart(sched, time.Now()).Format("2006-01-02 15:04:05"), nil
	}
	db.Exec(`UPDATE peers SET last_seen=datetime('now') WHERE token=?`, token)
	return "approved", "", "", nil
}

func (db *DB) RecordTraffic(token string, up, down int64) {
	db.Exec(`UPDATE peers SET bytes_up=bytes_up+?, bytes_down=bytes_down+?, last_seen=datetime('now') WHERE token=?`, up, down, token)
	if up != 0 || down != 0 {
		db.TrackDaily(token, up, down)
	}
}

// TrackDaily upserts today's cumulative traffic per token.
func (db *DB) TrackDaily(token string, up, down int64) {
	db.Exec(`CREATE TABLE IF NOT EXISTS daily_usage(token TEXT, day TEXT, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0, PRIMARY KEY(token, day))`)
	db.Exec(`INSERT INTO daily_usage(token, day, up, down) VALUES(?, date('now'), ?, ?)
	         ON CONFLICT(token, day) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, token, up, down)
}

// WeeklyReport: aggregated totals for the last 7 days across all tokens.
func (db *DB) WeeklyReport() []map[string]any {
	rows, err := db.Query(`SELECT day, SUM(up) as up, SUM(down) as down FROM daily_usage GROUP BY day ORDER BY day DESC LIMIT 7`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var day string
		var up, down int64
		rows.Scan(&day, &up, &down)
		out = append(out, map[string]any{"day": day, "up": up, "down": down})
	}
	return out
}

func (db *DB) IsBlocked(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	for _, d := range db.blockedSuffixes() {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
