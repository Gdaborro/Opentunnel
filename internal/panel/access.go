package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"opentunnel/internal/access"
)

// AccessPolicy reads admission, identity, limits and global policy in ONE SQL
// statement. Separate cached reads could combine an old allowlist with a new
// kill switch, or an approved verdict with a replacement public key.
func (db *DB) AccessPolicy(token string) (access.Snapshot, error) {
	if db == nil || db.DB == nil {
		return access.Snapshot{Status: "pending"}, errors.New("panel policy unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return accessPolicy(ctx, db, token)
}

type policyReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func accessPolicy(ctx context.Context, reader policyReader, token string) (access.Snapshot, error) {
	p := access.Snapshot{Status: "pending"}
	var kickReason, banReason, identityReason, kickExpiry, expiry, schedule string
	var kill, allow, sshMax, sshDaily, sshTrickle string
	var identityBanned bool
	err := reader.QueryRowContext(ctx, `SELECT p.status, COALESCE(p.kick_reason,''),
		COALESCE(p.ban_reason,''), COALESCE(p.kick_expires,''), COALESCE(p.expires_at,''),
		COALESCE(p.ssh_pubkey,''), COALESCE(p.auth_epoch,''), COALESCE(p.schedule,''),
		COALESCE(p.max_bps,0), COALESCE(p.quota_bytes,0), COALESCE(p.bytes_up,0)+COALESCE(p.bytes_down,0),
		(f.fingerprint IS NOT NULL OR k.pubkey IS NOT NULL), COALESCE(f.reason,k.reason,''),
		COALESCE((SELECT value FROM settings WHERE key='kill_switch'),'0'),
		COALESCE((SELECT value FROM settings WHERE key='kill_switch_reason'),''),
		COALESCE((SELECT value FROM settings WHERE key='kill_switch_allow'),''),
		COALESCE((SELECT value FROM settings WHERE key='ssh_tier_max_bps'),'0'),
		COALESCE((SELECT value FROM settings WHERE key='ssh_tier_daily_mb'),'0'),
		COALESCE((SELECT value FROM settings WHERE key='ssh_tier_trickle_kbps'),'0'),
		COALESCE((SELECT up+down FROM ingress_usage WHERE token=p.token AND ingress='ssh' AND day=date('now')),0),
		(p.v5_seen IS NOT NULL AND p.v5_seen!='')
		FROM peers p LEFT JOIN fingerprints_banned f ON f.fingerprint=p.fingerprint
		LEFT JOIN pubkeys_banned k ON k.pubkey=p.ssh_pubkey WHERE p.token=?`, token).
		Scan(&p.Status, &kickReason, &banReason, &kickExpiry, &expiry, &p.PublicKey,
			&p.Generation, &schedule, &p.MaxBps, &p.QuotaBytes, &p.UsedBytes,
			&identityBanned, &identityReason, &kill, &p.KillReason, &allow,
			&sshMax, &sshDaily, &sshTrickle, &p.SSHUsedBytes, &p.V5Seen)
	if err != nil {
		return p, err
	}
	switch strings.TrimSpace(kill) {
	case "", "0":
	case "1":
		p.KillSwitch = true
	default:
		return p, errors.New("invalid kill-switch policy")
	}
	for _, t := range strings.Split(allow, ",") {
		if strings.TrimSpace(t) == token {
			p.KillAllowed = true
		}
	}
	values := []struct {
		raw string
		max int64
		dst *int64
	}{{sshMax, 1_000_000_000, &p.SSHMaxBps}, {sshDaily, 1_000_000, &p.SSHDailyBytes}, {sshTrickle, 1_000_000, &p.SSHTrickleBps}}
	for _, v := range values {
		raw := strings.TrimSpace(v.raw)
		if raw == "" {
			raw = "0"
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 || n > v.max {
			return p, errors.New("invalid SSH containment policy")
		}
		*v.dst = n
	}
	p.SSHDailyBytes <<= 20
	p.SSHTrickleBps = p.SSHTrickleBps * 1000 / 8
	if p.SSHDailyBytes > 0 && p.SSHTrickleBps == 0 {
		p.SSHTrickleBps = defaultSSHTrickleBps
	}
	if p.MaxBps < 0 || p.QuotaBytes < 0 || p.UsedBytes < 0 {
		return p, errors.New("invalid device limits")
	}
	if identityBanned || p.Status == "banned" {
		p.Status, p.Reason = "banned", banReason
		if p.Reason == "" {
			p.Reason = identityReason
		}
		if p.Reason == "" {
			p.Reason = "device identity banned"
		}
		return p, nil
	}
	if p.Status == "kicked" {
		if kickExpiry == "" {
			p.Reason = kickReason
			return p, nil
		}
		exp, err := policyTime(kickExpiry)
		if err != nil {
			return p, fmt.Errorf("invalid kick expiry: %w", err)
		}
		if time.Now().Before(exp) {
			p.Reason, p.Expires = kickReason, exp.UTC().Format("2006-01-02 15:04:05")
			return p, nil
		}
		// An expired temporary kick is effectively approved without a write
		// on the hot path. The reaper reconciles the stored state later.
		p.Status = "approved"
	}
	switch p.Status {
	case "pending", "expired":
		return p, nil
	case "approved":
	default:
		return p, errors.New("unknown admission state")
	}
	if expiry != "" {
		exp, err := policyTime(expiry)
		if err != nil {
			return p, fmt.Errorf("invalid device expiry: %w", err)
		}
		if !time.Now().Before(exp) {
			p.Status = "expired"
			return p, nil
		}
	}
	if p.QuotaBytes > 0 && p.UsedBytes >= p.QuotaBytes {
		p.Status, p.Reason = "kicked", "data quota exceeded"
		return p, nil
	}
	if !ValidateSchedule(schedule) {
		return p, errors.New("invalid access schedule")
	}
	if !scheduleAllows(schedule, time.Now()) {
		p.Status, p.Reason = "kicked", "outside allowed hours (schedule)"
		p.Expires = nextScheduleStart(schedule, time.Now()).UTC().Format("2006-01-02 15:04:05")
	}
	return p, nil
}

func policyTime(raw string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339Nano, "2006-01-02 15:04:05 -0700 MST"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("unrecognized time format")
}

// ReserveTraffic durably accounts a bounded write BEFORE it reaches the
// target. This makes quota enforcement aggregate across TCP, UDP, sessions
// and relay processes. A crash may overcount an in-flight reserved chunk;
// it cannot silently grant an unlimited long-running stream.
func (db *DB) ReserveTraffic(parent context.Context, token, generation, ingress string, down bool, requested int) (access.Reservation, error) {
	r := access.Reservation{}
	if requested <= 0 || requested > 65535 {
		return r, errors.New("invalid traffic reservation size")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	release, err := db.accountSlot(ctx)
	if err != nil {
		return r, err
	}
	defer release()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT date('now')`).Scan(&r.Day); err != nil {
		return r, err
	}
	p, err := accessPolicy(ctx, tx, token)
	if err != nil {
		return r, err
	}
	if p.Generation != generation || p.Status != "approved" || (p.KillSwitch && !p.KillAllowed) {
		return r, errors.New("traffic identity or policy changed")
	}
	n := requested
	if p.QuotaBytes > 0 && int64(n) > p.QuotaBytes-p.UsedBytes {
		n = int(max(int64(0), p.QuotaBytes-p.UsedBytes))
	}
	if n == 0 {
		return r, errors.New("data quota exceeded")
	}
	upBytes, downBytes := n, 0
	if down {
		upBytes, downBytes = 0, n
	}
	res, err := tx.ExecContext(ctx, `UPDATE peers SET bytes_up=bytes_up+?, bytes_down=bytes_down+?, last_seen=datetime('now')
		WHERE token=? AND auth_epoch=? AND status IN ('approved','kicked')
		AND (COALESCE(quota_bytes,0)=0 OR COALESCE(bytes_up,0)+COALESCE(bytes_down,0)+? <= quota_bytes)`, upBytes, downBytes, token, generation, n)
	if err != nil {
		return r, err
	}
	if rows, err := res.RowsAffected(); err != nil || rows != 1 {
		return r, errors.New("traffic admission changed")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO daily_usage(token,day,up,down) VALUES(?,?,?,?)
		ON CONFLICT(token,day) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, token, r.Day, upBytes, downBytes); err != nil {
		return r, err
	}
	if ingress != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ingress_usage(token,ingress,day,up,down) VALUES(?,?,?,?,?)
			ON CONFLICT(token,ingress,day) DO UPDATE SET up=up+excluded.up, down=down+excluded.down`, token, ingress, r.Day, upBytes, downBytes); err != nil {
			return r, err
		}
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	r.Bytes = n
	return r, nil
}

// RefundTraffic undoes the untransmitted portion of a reservation. An update
// is generation-bound so an old stream cannot refund a replacement identity.
func (db *DB) RefundTraffic(parent context.Context, token, generation, ingress string, down bool, reservation access.Reservation, n int) error {
	if n <= 0 {
		return nil
	}
	if n > reservation.Bytes {
		return errors.New("refund exceeds reservation")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	release, err := db.accountSlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	column := "up"
	if down {
		column = "down"
	}
	res, err := tx.ExecContext(ctx, `UPDATE peers SET bytes_`+column+`=MAX(0,bytes_`+column+`-?) WHERE token=? AND auth_epoch=?`, n, token, generation)
	if err != nil {
		return err
	}
	if rows, err := res.RowsAffected(); err != nil || rows != 1 {
		return errors.New("refund identity changed")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE daily_usage SET `+column+`=MAX(0,`+column+`-?) WHERE token=? AND day=?`, n, token, reservation.Day); err != nil {
		return err
	}
	if ingress != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE ingress_usage SET `+column+`=MAX(0,`+column+`-?) WHERE token=? AND ingress=? AND day=?`, n, token, ingress, reservation.Day); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) accountSlot(ctx context.Context) (func(), error) {
	if db == nil || db.DB == nil {
		return nil, errors.New("accounting unavailable")
	}
	db.accountMu.Lock()
	if db.accountGate == nil {
		db.accountGate = make(chan struct{}, 1)
	}
	gate := db.accountGate
	db.accountMu.Unlock()
	select {
	case gate <- struct{}{}:
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ interface {
	AccessPolicy(string) (access.Snapshot, error)
} = (*DB)(nil)
