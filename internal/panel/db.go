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
}

func (db *DB) IsBlocked(domain string) bool {
	var c int
	db.QueryRow(`SELECT COUNT(*) FROM blocklist WHERE domain=?`, domain).Scan(&c)
	return c > 0
}
