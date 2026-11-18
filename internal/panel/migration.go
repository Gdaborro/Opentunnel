package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"opentunnel/internal/authority"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/serverpool"
)

type ChannelMigrationReport struct {
	PoolID            string `json:"pool_id"`
	AuthorityID       string `json:"authority_id"`
	CurrentlyRequired bool   `json:"currently_required"`
	Approved          int    `json:"approved_devices"`
	Verified          int    `json:"channel_verified_devices"`
	NotVerified       int    `json:"unverified_approved_devices"`
	OutstandingGrants int    `json:"outstanding_grants"`
}

func (db *DB) ChannelMigrationReport(parent context.Context) (ChannelMigrationReport, error) {
	var report ChannelMigrationReport
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT pool_id,authority_id,channel_required FROM server_pool_authority WHERE id=1`).Scan(&report.PoolID, &report.AuthorityID, &report.CurrentlyRequired); err != nil {
		return report, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(channel_seen=1 AND channel_epoch=auth_epoch AND auth_epoch!='' AND COALESCE(ssh_pubkey,'')!=''),0) FROM peers WHERE status IN ('approved','kicked')`).Scan(&report.Approved, &report.Verified); err != nil {
		return report, err
	}
	report.NotVerified = report.Approved - report.Verified
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM authority_reservations WHERE settled=0 AND created_at>?`, time.Now().Add(-authority.ReservationRetention).Unix()).Scan(&report.OutstandingGrants); err != nil {
		return report, err
	}
	return report, tx.Commit()
}

// EnablePoolChannelAuthentication is deliberately one-way and guarded. The
// operator must first canary every approved identity and preserve an exact
// verified backup. Merely starting a new relay never migrates stored policy.
func (db *DB) EnablePoolChannelAuthentication(parent context.Context, poolID, authorityID string) error {
	if !serverpool.ValidID(poolID) || !serverpool.ValidID(authorityID) {
		return errors.New("invalid migration scope")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var storedPool, storedAuthority string
	var required bool
	if err := tx.QueryRowContext(ctx, `SELECT pool_id,authority_id,channel_required FROM server_pool_authority WHERE id=1`).Scan(&storedPool, &storedAuthority, &required); err != nil {
		return err
	}
	if storedPool != poolID || storedAuthority != authorityID {
		return errors.New("migration authority mismatch")
	}
	var remaining int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers WHERE status IN ('approved','kicked') AND (channel_seen!=1 OR channel_epoch!=auth_epoch OR auth_epoch='' OR COALESCE(ssh_pubkey,'')='')`).Scan(&remaining); err != nil {
		return err
	}
	if remaining != 0 {
		return fmt.Errorf("%d approved devices have not completed a verified channel-authentication canary; migration refused", remaining)
	}
	if required {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `UPDATE server_pool_authority SET channel_required=1 WHERE id=1 AND pool_id=? AND authority_id=?`, poolID, authorityID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('auth-migration','operator enabled connection-bound pool authentication after all approved devices verified; rollback requires preserved pre-migration state')`); err != nil {
		return err
	}
	return tx.Commit()
}

// BackupDatabase uses SQLite's consistent VACUUM INTO snapshot, not a racy
// copy of a live WAL file. Output is private and new-only. This does not back up
// server TLS keys/configs and does not authorize deploying or restoring them.
func (db *DB) BackupDatabase(parent context.Context, destination string) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return errors.New("backup needs a new canonical absolute private path")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return errors.New("backup destination already exists or is unavailable")
	}
	if err := privatefile.EnsureDir(filepath.Dir(destination)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".otu-db-backup-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err := f.Close(); err != nil {
		return err
	}
	if err := privatefile.Protect(temporary); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	quoted := "'" + strings.ReplaceAll(temporary, "'", "''") + "'"
	if _, err := db.ExecContext(ctx, "VACUUM INTO "+quoted); err != nil {
		return err
	}
	copy, err := sql.Open("sqlite", temporary+"?mode=ro")
	if err != nil {
		return err
	}
	defer copy.Close()
	var check string
	if err := copy.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		return errors.New("database backup did not pass SQLite integrity check")
	}
	if err := copy.Close(); err != nil {
		return err
	}
	return os.Link(temporary, destination) // atomic no-replace publication of the complete private snapshot
}
