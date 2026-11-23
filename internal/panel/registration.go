package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var errRegistrationConflict = errors.New("stored bootstrap identity differs")
var errRegistrationDenied = errors.New("bootstrap identity banned or capacity reached")

type registrationRequest struct {
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	DeviceName  string `json:"device_name"`
	SSHPubKey   string `json:"ssh_pubkey"`
}

// registerBootstrap preserves the legacy default-operator enrollment contract,
// but reads identity bans, existing key/approval and the auto-accept window in
// the same writer transaction as any mutation and audit. No failed read/audit
// may partially enroll, backfill a key or revive an identity after a ban/rekey.
func (db *DB) registerBootstrap(parent context.Context, req registrationRequest, autoApprove bool) (status string, changed, created bool, err error) {
	key, valid := CanonicalSSHPubKey(req.SSHPubKey)
	if !validTokenCharset(req.Token) || !valid || len(req.Fingerprint) < 1 || len(req.Fingerprint) > 128 || len(req.DeviceName) > 64 {
		return "", false, false, errRegistrationDenied
	}
	req.SSHPubKey = key
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, false, err
	}
	defer tx.Rollback()
	var poolBound bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_pool_authority)`).Scan(&poolBound); err != nil {
		return "", false, false, err
	}
	if poolBound {
		return "", false, false, errors.New("signed pool enrollment required; bootstrap route cannot bypass authority binding")
	}
	var banned bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM fingerprints_banned WHERE fingerprint=?) OR EXISTS(SELECT 1 FROM pubkeys_banned WHERE pubkey=?)`, req.Fingerprint, key).Scan(&banned); err != nil {
		return "", false, false, err
	}
	if banned {
		return "", false, false, errRegistrationDenied
	}
	var window string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT value FROM settings WHERE key='auto_accept_until'),'')`).Scan(&window); err != nil {
		return "", false, false, err
	}
	autoAccept := false
	if strings.TrimSpace(window) != "" {
		until, err := policyTime(window)
		if err != nil {
			return "", false, false, errors.New("invalid auto-accept window")
		}
		autoAccept = time.Now().Before(until)
	}
	var existingKey, fp string
	var approvalRequired bool
	err = tx.QueryRowContext(ctx, `SELECT status,COALESCE(ssh_pubkey,''),fingerprint,approval_required FROM peers WHERE token=?`, req.Token).Scan(&status, &existingKey, &fp, &approvalRequired)
	if err == nil {
		if status == "banned" {
			return "", false, false, errRegistrationDenied
		}
		if fp != req.Fingerprint || (!sameSSHKey(existingKey, key) && !(existingKey == "" && status == "pending")) {
			return "", false, false, errRegistrationConflict
		}
		if status == "pending" {
			if existingKey == "" {
				if _, err := tx.ExecContext(ctx, `UPDATE peers SET ssh_pubkey=? WHERE token=? AND status='pending' AND COALESCE(ssh_pubkey,'')=''`, key, req.Token); err != nil {
					return "", false, false, err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('ssh-key','pending bootstrap key recorded; approval remains required')`); err != nil {
					return "", false, false, err
				}
				changed = true
			}
			if _, err := tx.ExecContext(ctx, `UPDATE peers SET last_seen=datetime('now') WHERE token=? AND status='pending'`, req.Token); err != nil {
				return "", false, false, err
			}
			if !approvalRequired && autoAccept {
				result, err := tx.ExecContext(ctx, `UPDATE peers SET status='approved' WHERE token=? AND status='pending' AND approval_required=0`, req.Token)
				if err != nil {
					return "", false, false, err
				}
				if n, err := result.RowsAffected(); err != nil || n != 1 {
					return "", false, false, errors.New("bootstrap approval changed")
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('auto-accept','default-operator bootstrap approved in explicitly open operator window')`); err != nil {
					return "", false, false, err
				}
				status, changed = "approved", true
			}
		}
		return status, changed, false, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return "", false, false, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers`).Scan(&count); err != nil {
		return "", false, false, err
	}
	if count >= 4096 {
		return "", false, false, errRegistrationDenied
	}
	status = "pending"
	if autoApprove || autoAccept {
		status = "approved"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO peers(token,fingerprint,device_name,ssh_pubkey,status,created_at,last_seen,auth_epoch) VALUES(?,?,?,?,?,datetime('now'),datetime('now'),hex(randomblob(16)))`, req.Token, req.Fingerprint, req.DeviceName, key, status); err != nil {
		return "", false, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('register',?)`, fmt.Sprintf("default-operator bootstrap created (%s); admission is operator policy", status)); err != nil {
		return "", false, false, err
	}
	return status, true, true, tx.Commit()
}
