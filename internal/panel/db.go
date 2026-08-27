package panel

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	go reaper(db)
	return &DB{db}, nil
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
	CREATE INDEX IF NOT EXISTS idx_peers_status ON peers(status);
	CREATE INDEX IF NOT EXISTS idx_peers_fingerprint ON peers(fingerprint);
	`)
	return err
}

func reaper(db *sql.DB) {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		db.Exec(`UPDATE peers SET status='expired' WHERE status='approved' AND last_seen < datetime('now', '-10 days')`)
		db.Exec(`UPDATE peers SET status='approved', kick_expires=NULL, kick_reason=NULL WHERE status='kicked' AND kick_expires < datetime('now')`)
	}
}

type Peer struct {
	Token       string
	Fingerprint string
	DeviceName  string
	Status      string
	CreatedAt   time.Time
	LastSeen    time.Time
	ExpiresAt   *time.Time
	BytesUp     int64
	BytesDown   int64
	KickExpires *time.Time
	KickReason  string
	BanReason   string
	BanDuration string
}

func (db *DB) CheckToken(token string) (status, reason, kickExpires string, err error) {
	var s, kr, br, ke string
	err = db.QueryRow(`SELECT status, COALESCE(kick_reason,''), COALESCE(ban_reason,''), COALESCE(kick_expires,'') FROM peers WHERE token=?`, token).Scan(&s, &kr, &br, &ke)
	if err != nil {
		return "pending", "", "", nil
	}
	if s == "banned" {
		return "banned", br, "", nil
	}
	if s == "kicked" {
		return "kicked", kr, ke, nil
	}
	if s == "pending" || s == "expired" {
		return s, "", "", nil
	}
	// approved — update last_seen
	db.Exec(`UPDATE peers SET last_seen=datetime('now') WHERE token=?`, token)
	return "approved", "", "", nil
}

func (db *DB) RecordTraffic(token string, up, down int64) {
	db.Exec(`UPDATE peers SET bytes_up=bytes_up+?, bytes_down=bytes_down+?, last_seen=datetime('now') WHERE token=?`, up, down, token)
	if up != 0 || down != 0 {
		db.TrackDaily(token, up, down)
	}
}

// CreateLegacyPeer registers IP-derived clients so they show in the UI.
func (db *DB) CreateLegacyPeer(token string) {
	db.Exec(`INSERT OR IGNORE INTO peers(token,fingerprint,device_name,status,created_at,last_seen,ssh_pubkey) VALUES(?,?,?,'approved',datetime('now'),datetime('now'),NULL)`,
		token, token, token)
	db.Exec(`UPDATE peers SET last_seen=datetime('now') WHERE token=?`, token)
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
	var c int
	db.QueryRow(`SELECT COUNT(*) FROM blocklist WHERE domain=?`, domain).Scan(&c)
	return c > 0
}
