package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PeerStateAction changes admission and identity bans atomically with its
// audit event. Failed writes must never be reported as a successful policy
// action, and a kick cannot revive a pending/rekey/expired/banned identity.
func (db *DB) PeerStateAction(token, action, reason, duration string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status, fp, pub string
	if err := tx.QueryRowContext(ctx, `SELECT status,fingerprint,COALESCE(ssh_pubkey,'') FROM peers WHERE token=?`, token).Scan(&status, &fp, &pub); err != nil {
		return err
	}
	var query string
	var args []any
	switch action {
	case "approve":
		var banned int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM fingerprints_banned WHERE fingerprint=?) OR EXISTS(SELECT 1 FROM pubkeys_banned WHERE pubkey=?)`, fp, pub).Scan(&banned); err != nil {
			return err
		}
		if status == "banned" || banned != 0 || pub == "" {
			return errors.New("identity must be verified and unbanned before approval")
		}
		query = `UPDATE peers SET status='approved',approval_required=0,kick_reason=NULL,kick_expires=NULL,last_seen=datetime('now') WHERE token=?`
		args = []any{token}
	case "kick":
		if status != "approved" && status != "kicked" {
			return errors.New("only an approved identity can be temporarily kicked")
		}
		query = `UPDATE peers SET status='kicked',kick_reason=?,kick_expires=datetime('now','+10 minutes') WHERE token=?`
		args = []any{reason, token}
	case "ban":
		if fp != "" {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO fingerprints_banned(fingerprint,reason,banned_at) VALUES(?,?,datetime('now'))`, fp, reason); err != nil {
				return err
			}
		}
		if pub != "" {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO pubkeys_banned(pubkey,reason,banned_at) VALUES(?,?,datetime('now'))`, pub, reason); err != nil {
				return err
			}
		}
		query = `UPDATE peers SET status='banned',ban_reason=?,ban_duration=?,auth_epoch=hex(randomblob(16)) WHERE token=?`
		args = []any{reason, duration, token}
	case "unban":
		if _, err := tx.ExecContext(ctx, `DELETE FROM fingerprints_banned WHERE fingerprint=?`, fp); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM pubkeys_banned WHERE pubkey=?`, pub); err != nil {
			return err
		}
		query = `UPDATE peers SET status='pending',approval_required=1,auth_epoch=hex(randomblob(16)),ban_reason=NULL,ban_duration=NULL,kick_reason=NULL,kick_expires=NULL WHERE token=?`
		args = []any{token}
	case "expire":
		if status == "banned" {
			return errors.New("banned identity must be unbanned explicitly")
		}
		query = `UPDATE peers SET status='expired',approval_required=1,auth_epoch=hex(randomblob(16)),kick_reason=NULL,kick_expires=NULL WHERE token=?`
		args = []any{token}
	case "delete":
		// Deleting a device row is not an unban. Preserve the durable banned
		// fingerprint/key so a deletion cannot silently remove enforcement.
		for _, table := range []string{"daily_usage", "ingress_usage", "visits", "device_health", "peer_ips"} {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE token=?`, token); err != nil {
				return err
			}
		}
		query = `DELETE FROM peers WHERE token=?`
		args = []any{token}
	case "reset":
		if _, err := tx.ExecContext(ctx, `DELETE FROM daily_usage WHERE token=?`, token); err != nil {
			return err
		}
		query = `UPDATE peers SET bytes_up=0,bytes_down=0 WHERE token=?`
		args = []any{token}
	default:
		return errors.New("unknown admission action")
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return sql.ErrNoRows
	}
	short := token
	if len(short) > 8 {
		short = short[:8]
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES(?,?)`, action, fmt.Sprintf("device %s: %s", short, action)); err != nil {
		return err
	}
	return tx.Commit()
}
