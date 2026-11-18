package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PeerStateAction changes admission and identity bans atomically with its
// audit event. Failed writes must never be reported as a successful policy
// action, and a kick cannot revive a pending/rekey/expired/banned identity.
func (db *DB) PeerStateAction(token, action, reason, duration string) error {
	if !validTokenCharset(token) || len(reason) > 500 || len(duration) > 64 {
		return errors.New("invalid admission action")
	}
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
	if key, ok := CanonicalSSHPubKey(pub); ok {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO managed_ssh_keys(public_key,desired) VALUES(?,0)`, key); err != nil {
			return err
		}
	}
	var query string
	var args []any
	switch action {
	case "approve":
		p, err := accessPolicy(ctx, tx, token)
		if err != nil {
			return err
		}
		if p.PoolID != "" && !p.Enrolled {
			return errors.New("signed pool enrollment is required before administrator approval")
		}
		var banned int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM fingerprints_banned WHERE fingerprint=?) OR EXISTS(SELECT 1 FROM pubkeys_banned WHERE pubkey=?)`, fp, pub).Scan(&banned); err != nil {
			return err
		}
		_, validKey := CanonicalSSHPubKey(pub)
		if status == "banned" || banned != 0 || !validKey {
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
		for _, table := range []string{"daily_usage", "ingress_usage", "visits", "device_health", "peer_ips", "peer_enrollments"} {
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
		query = `UPDATE peers SET bytes_up=0,bytes_down=0,auth_epoch=hex(randomblob(16)) WHERE token=?`
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

// RekeyPeer verifies the exact old key and admission in the same transaction
// as the replacement, audit event and durable SSH ownership. A failed audit
// cannot remove a working SSH key or leave a silently replaced identity.
func (db *DB) RekeyPeer(token, expected, replacement string) (bool, error) {
	pub, ok := CanonicalSSHPubKey(replacement)
	if !validTokenCharset(token) || !ok || len(expected) > 2048 {
		return false, errors.New("invalid key replacement")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var old, fp, status string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(ssh_pubkey,''),fingerprint,status FROM peers WHERE token=?`, token).Scan(&old, &fp, &status); err != nil {
		return false, err
	}
	if strings.TrimSpace(expected) != strings.TrimSpace(old) {
		return false, errors.New("stored key changed; refresh before confirming replacement")
	}
	var banned int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM fingerprints_banned WHERE fingerprint=?) OR EXISTS(SELECT 1 FROM pubkeys_banned WHERE pubkey IN (?,?))`, fp, old, pub).Scan(&banned); err != nil {
		return false, err
	}
	if status == "banned" || banned != 0 {
		return false, errors.New("identity must be unbanned before replacing its key")
	}
	if sameSSHKey(old, pub) {
		return false, tx.Commit()
	}
	result, err := tx.ExecContext(ctx, `UPDATE peers SET ssh_pubkey=?,status='pending',approval_required=1,auth_epoch=hex(randomblob(16)) WHERE token=? AND COALESCE(ssh_pubkey,'')=?`, pub, token, old)
	if err != nil {
		return false, err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return false, errors.New("key replacement identity changed")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('ssh-key','administrator verified key replacement; separate approval required')`); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (db *DB) SetPeerLimitsChecked(token, schedule string, maxBps, quotaBytes int64) error {
	if !validTokenCharset(token) || !ValidateSchedule(schedule) || maxBps < 0 || quotaBytes < 0 {
		return errors.New("invalid device limits")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE peers SET schedule=?,max_bps=?,quota_bytes=? WHERE token=?`, strings.TrimSpace(schedule), maxBps, quotaBytes, token)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('limits','device limits updated by administrator')`); err != nil {
		return err
	}
	return tx.Commit()
}
