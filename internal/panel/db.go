package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
	accountGate                  chan struct{}
	done                         chan struct{}
	closeOnce                    sync.Once
	accountMu                    sync.Mutex // serialize traffic reservations within this process
	block                        blockCache
	policyMu                     sync.Mutex
	killOn                       bool
	killAt                       time.Time
	killReason                   string
	killAllow                    map[string]bool
	killDetailAt                 time.Time
	sshMax, sshDaily, sshTrickle int64
	sshAt                        time.Time
}

func Open(path string, purgeAfterDays int) (*DB, error) {
	// WAL mode is configured on a bounded dedicated migration connection.
	// Putting its pragma in every lazy connection initializer can return
	// SQLITE_BUSY immediately when relay/panel open the same file together.
	// Every explicit transaction in this package writes. Acquire its writer
	// lock BEFORE reading admission/accounting snapshots. Deferred read-to-write
	// upgrades can return SQLITE_BUSY_SNAPSHOT immediately when an independent
	// relay/panel metadata write commits between the read and the reservation.
	// busy_timeout cannot retry that stale snapshot; BEGIN IMMEDIATE avoids it.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	wrapped := &DB{DB: db, done: make(chan struct{})}
	go reaper(wrapped, purgeAfterDays)
	return wrapped, nil
}

func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	db.closeOnce.Do(func() {
		if db.done != nil {
			close(db.done)
		}
	})
	return db.DB.Close()
}

type schemaDB interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}
type schemaConn struct {
	conn *sql.Conn
	ctx  context.Context
}

func (s schemaConn) Exec(q string, args ...any) (sql.Result, error) {
	return s.conn.ExecContext(s.ctx, q, args...)
}
func (s schemaConn) QueryRow(q string, args ...any) *sql.Row {
	return s.conn.QueryRowContext(s.ctx, q, args...)
}

// Relay and panel may start together. Serialize migrations at the database
// write lock, not with a process-local mutex or a racy check-then-ALTER pair.
func migrate(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := schemaExecRetry(ctx, conn, "PRAGMA journal_mode=WAL"); err != nil {
		return err
	}
	if err := schemaExecRetry(ctx, conn, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	if err := migrateSchema(schemaConn{conn: conn, ctx: ctx}); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func schemaExecRetry(ctx context.Context, conn *sql.Conn, query string) error {
	for {
		_, err := conn.ExecContext(ctx, query)
		if !sqliteBusy(err) {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func sqliteBusy(err error) bool {
	if err == nil {
		return false
	}
	var code interface{ Code() int }
	if errors.As(err, &code) {
		return code.Code()&0xff == 5 || code.Code()&0xff == 6
	}
	return false
}

// sqliteLockContention is plain SQLITE_BUSY (5), not BUSY_SNAPSHOT (6).
// Retrying the latter would only repeat a stale read; immediate transactions
// and fail-closed handling are required instead.
func sqliteLockContention(err error) bool {
	if err == nil {
		return false
	}
	var code interface{ Code() int }
	if errors.As(err, &code) {
		return code.Code()&0xff == 5
	}
	return false
}

func migrateSchema(db schemaDB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS admins (
		id INTEGER PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS enrollment_accounts (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
		max_devices INTEGER NOT NULL DEFAULT 5 CHECK(max_devices BETWEEN 1 AND 32),
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS peer_enrollments (
		token TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		pool_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_peer_enrollments_username ON peer_enrollments(username);
	CREATE TABLE IF NOT EXISTS server_pool_authority (
		id INTEGER PRIMARY KEY CHECK(id=1),
		pool_id TEXT NOT NULL,
		authority_id TEXT NOT NULL,
		login_required INTEGER NOT NULL CHECK(login_required IN (0,1))
	);
	CREATE TABLE IF NOT EXISTS pool_http_proofs (
		nonce TEXT PRIMARY KEY,
		valid_until INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS managed_ssh_keys (
		public_key TEXT PRIMARY KEY,
		desired INTEGER NOT NULL CHECK(desired IN (0,1)),
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS authority_reservations (
		id TEXT PRIMARY KEY,
		node_id TEXT NOT NULL,
		token TEXT NOT NULL,
		generation TEXT NOT NULL,
		ingress TEXT NOT NULL,
		down INTEGER NOT NULL CHECK(down IN (0,1)),
		requested INTEGER NOT NULL,
		bytes INTEGER NOT NULL,
		day TEXT NOT NULL,
		ready_at INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		settled INTEGER NOT NULL DEFAULT 0 CHECK(settled IN (0,1)),
		refund INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS authority_reservations_node ON authority_reservations(node_id,settled);
	CREATE INDEX IF NOT EXISTS authority_reservations_peer ON authority_reservations(token,settled);
	CREATE INDEX IF NOT EXISTS authority_reservations_time ON authority_reservations(created_at);
	CREATE TABLE IF NOT EXISTS authority_rates (
		token TEXT NOT NULL,
		scope TEXT NOT NULL,
		generation TEXT NOT NULL,
		next_ns INTEGER NOT NULL,
		PRIMARY KEY(token,scope)
	);
	CREATE TABLE IF NOT EXISTS authority_node_metrics (
		node_id TEXT PRIMARY KEY,
		snapshot TEXT NOT NULL,
		at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS authority_node_events (
		node_id TEXT PRIMARY KEY,
		window INTEGER NOT NULL,
		count INTEGER NOT NULL
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
	CREATE TABLE IF NOT EXISTS ingress_usage (
		token TEXT NOT NULL,
		ingress TEXT NOT NULL,
		day TEXT NOT NULL,
		up INTEGER NOT NULL DEFAULT 0,
		down INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY(token, ingress, day)
	);
	CREATE INDEX IF NOT EXISTS idx_peers_status ON peers(status);
	CREATE INDEX IF NOT EXISTS idx_peers_fingerprint ON peers(fingerprint);
	CREATE INDEX IF NOT EXISTS idx_visits_domain ON visits(domain);
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT
	);
	CREATE TABLE IF NOT EXISTS relay_metrics (
		id INTEGER PRIMARY KEY CHECK(id=1),
		snapshot TEXT NOT NULL,
		at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	CREATE TABLE IF NOT EXISTS peer_ips (
		token TEXT NOT NULL,
		ip TEXT NOT NULL,
		at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_peer_ips_token ON peer_ips(token);
	CREATE INDEX IF NOT EXISTS idx_peer_ips_at ON peer_ips(at);
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
		// v5_seen: first signature-verified v5 session (audit round four:
		// sticky upgrade — once a peer proved key possession, v4
		// handshakes for its token are downgrade attempts).
		{"v5_seen", "DATETIME"},
		{"channel_seen", "INTEGER NOT NULL DEFAULT 0"},
		{"channel_epoch", "TEXT NOT NULL DEFAULT ''"},
		// Explicit approval cannot be confused with ordinary bootstrap state.
		{"approval_required", "INTEGER NOT NULL DEFAULT 0"},
		// A new generation invalidates already-authenticated sessions, even
		// if the identity is subsequently approved again or its key restored.
		{"auth_epoch", "TEXT NOT NULL DEFAULT ''"},
	} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peers') WHERE name=?`, col.name).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := db.Exec(`ALTER TABLE peers ADD COLUMN ` + col.name + ` ` + col.def); err != nil {
				return err
			}
		}
	}
	if _, err := db.Exec(`UPDATE peers SET auth_epoch=hex(randomblob(16)) WHERE auth_epoch=''`); err != nil {
		return err
	}
	for _, col := range []string{"pool_id", "public_key"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('peer_enrollments') WHERE name=?`, col).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := db.Exec(`ALTER TABLE peer_enrollments ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`); err != nil {
				return err
			}
		}
	}
	var channelColumn int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('server_pool_authority') WHERE name='channel_required'`).Scan(&channelColumn); err != nil {
		return err
	}
	if channelColumn == 0 {
		if _, err := db.Exec(`ALTER TABLE server_pool_authority ADD COLUMN channel_required INTEGER NOT NULL DEFAULT 0 CHECK(channel_required IN (0,1))`); err != nil {
			return err
		}
	}
	// Retain explicit key ownership across every writer (including reaper,
	// rekey and interrupted callbacks) before a peer row can disappear.
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO managed_ssh_keys(public_key,desired)
			SELECT ssh_pubkey,0 FROM peers WHERE COALESCE(ssh_pubkey,'')!='';
		CREATE TRIGGER IF NOT EXISTS managed_ssh_peer_insert AFTER INSERT ON peers
			WHEN COALESCE(NEW.ssh_pubkey,'')!='' BEGIN
			INSERT OR IGNORE INTO managed_ssh_keys(public_key,desired) VALUES(NEW.ssh_pubkey,0); END;
		CREATE TRIGGER IF NOT EXISTS managed_ssh_peer_update AFTER UPDATE OF ssh_pubkey,status ON peers BEGIN
			INSERT OR IGNORE INTO managed_ssh_keys(public_key,desired) SELECT OLD.ssh_pubkey,0 WHERE COALESCE(OLD.ssh_pubkey,'')!='';
			INSERT OR IGNORE INTO managed_ssh_keys(public_key,desired) SELECT NEW.ssh_pubkey,0 WHERE COALESCE(NEW.ssh_pubkey,'')!=''; END;
		CREATE TRIGGER IF NOT EXISTS managed_ssh_peer_delete BEFORE DELETE ON peers
			WHEN COALESCE(OLD.ssh_pubkey,'')!='' BEGIN
			INSERT OR IGNORE INTO managed_ssh_keys(public_key,desired) VALUES(OLD.ssh_pubkey,0); END;
	`); err != nil {
		return err
	}
	// Seed the built-in categories (disabled until an admin enables them).
	for _, column := range []struct{ name, definition string }{{"update_channel", "TEXT NOT NULL DEFAULT ''"}, {"update_state", "TEXT NOT NULL DEFAULT ''"}, {"channel_authentication", "INTEGER NOT NULL DEFAULT 0"}} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('device_health') WHERE name=?`, column.name).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			if _, err := db.Exec(`ALTER TABLE device_health ADD COLUMN ` + column.name + ` ` + column.definition); err != nil {
				return err
			}
		}
	}
	for cat := range categoryLists {
		if _, err := db.Exec(`INSERT OR IGNORE INTO blocked_categories(category,enabled) VALUES(?,0)`, cat); err != nil {
			return err
		}
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
	defer ticker.Stop()
	for {
		select {
		case <-db.done:
			return
		case <-ticker.C:
			db.Exec(`DELETE FROM peers WHERE status IN ('approved','pending','expired','kicked') AND last_seen < datetime('now', ?)`, window)
			db.Exec(`DELETE FROM visits WHERE token NOT IN (SELECT token FROM peers)`)
			db.Exec(`DELETE FROM daily_usage WHERE token NOT IN (SELECT token FROM peers)`)
			db.Exec(`DELETE FROM ingress_usage WHERE token NOT IN (SELECT token FROM peers) OR day < date('now','-30 days')`)
			db.Exec(`DELETE FROM device_health WHERE token NOT IN (SELECT token FROM peers)`)
			db.Exec(`DELETE FROM peer_enrollments WHERE token NOT IN (SELECT token FROM peers)`)
			db.Exec(`DELETE FROM authority_rates WHERE token NOT IN (SELECT token FROM peers)`)
			db.Exec(`DELETE FROM peer_ips WHERE token NOT IN (SELECT token FROM peers)`)
			_ = db.PrunePrivacyRetention(context.Background())
			db.Exec(`UPDATE peers SET status='approved', kick_expires=NULL, kick_reason=NULL WHERE status='kicked' AND kick_expires IS NOT NULL AND kick_expires < datetime('now')`)
			db.Exec(`DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)`)
			db.offlineSweep()
		}
	}
}

// RecordEvent appends to the panel event feed (pruned by the reaper).
func (db *DB) RecordEvent(kind, detail string) {
	db.Exec(`INSERT INTO events(kind,detail,at) VALUES(?,?,datetime('now'))`, kind, detail)
}

// RecentEvents returns the newest events for the panel feed.
// Legacy callers receive nil on unavailable reads; HTTP uses RecentEventsChecked.
func (db *DB) RecentEvents(limit int) []map[string]string {
	out, _ := db.RecentEventsChecked(context.Background(), limit)
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
	if db == nil {
		return "pending", "", "", nil
	}
	p, err := db.AccessPolicy(token)
	if err == sql.ErrNoRows {
		return "pending", "", "", nil
	}
	if err != nil {
		return "pending", "", "", err
	}
	return p.Status, p.Reason, p.Expires, nil
}

func (db *DB) RecordTraffic(token string, up, down int64) {
	if db == nil {
		return
	}
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
	if db == nil {
		return false
	}
	blocked, _, err := db.CheckBlocked(domain)
	return blocked || err != nil
}
