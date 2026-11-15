package panel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"opentunnel/internal/serverpool"
)

// BindServerPool fixes this database to one operator identity. Panel and relay
// call it before serving any request. A missing pool_id must not silently
// disable enrollment checks on a database that was already pool-scoped.
// SQLite is a single-host authority, not a multi-host replication protocol.
func (db *DB) BindServerPool(id string, loginRequired bool) (serverpool.Info, error) {
	var info serverpool.Info
	if (id != "" && !serverpool.ValidID(id)) || (id == "" && loginRequired) {
		return info, errors.New("invalid server pool authority configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return info, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT pool_id,authority_id,login_required FROM server_pool_authority WHERE id=1`).Scan(&info.PoolID, &info.AuthorityID, &info.LoginRequired)
	if err == sql.ErrNoRows {
		if id == "" {
			return info, tx.Commit()
		}
		var random [32]byte
		if _, err := rand.Read(random[:]); err != nil {
			return info, err
		}
		info.PoolID, info.AuthorityID, info.LoginRequired = id, hex.EncodeToString(random[:]), loginRequired
		if _, err := tx.ExecContext(ctx, `INSERT INTO server_pool_authority(id,pool_id,authority_id,login_required) VALUES(1,?,?,?)`, id, info.AuthorityID, loginRequired); err != nil {
			return info, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('server-pool','database bound to an operator pool; existing devices need signed enrollment and manual approval')`); err != nil {
			return info, err
		}
	} else if err != nil {
		return info, err
	} else {
		if info.PoolID != id || !serverpool.ValidID(info.AuthorityID) {
			return info, errors.New("database belongs to another pool, or configured pool_id was removed; authority preserved")
		}
		if info.LoginRequired != loginRequired {
			return info, errors.New("enrollment_login differs from the bound authority; policy migration is not automatic (keep relay and panel configuration identical)")
		}
	}
	info.Version, info.ApprovalRequired = serverpool.ProfileVersion, true
	return info, tx.Commit()
}
