package panel

import (
	"context"
	"errors"
	"time"
)

// ReconcileSSH maintains ownership in a durable inventory so a removed peer
// row or missed hook does not lose revocation intent. Operator entries that
// were never managed are preserved. SQL failure never becomes an empty desired
// set that clears an operator's entire authorized_keys file.
func (db *DB) ReconcileSSH(path, target string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT public_key FROM managed_ssh_keys LIMIT 4097`)
	if err != nil {
		return 0, err
	}
	managed := map[string]bool{}
	rowCount := 0
	for rows.Next() {
		rowCount++
		if rowCount > 4096 {
			rows.Close()
			return 0, errors.New("managed SSH inventory capacity exceeded")
		}
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return 0, err
		}
		if canonical, ok := CanonicalSSHPubKey(key); ok {
			managed[canonical] = true
		}
		if len(managed) > 4096 {
			rows.Close()
			return 0, errors.New("managed SSH inventory capacity exceeded")
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	rows, err = tx.QueryContext(ctx, `SELECT token,COALESCE(ssh_pubkey,'') FROM peers WHERE COALESCE(ssh_pubkey,'')!='' LIMIT 4097`)
	if err != nil {
		return 0, err
	}
	type peerKey struct{ token, key string }
	peers := []peerKey{}
	for rows.Next() {
		var p peerKey
		if err := rows.Scan(&p.token, &p.key); err != nil {
			rows.Close()
			return 0, err
		}
		peers = append(peers, p)
		if len(peers) > 4096 {
			rows.Close()
			return 0, errors.New("SSH peer inventory capacity exceeded")
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	desired := map[string]bool{}
	for _, peer := range peers {
		key, ok := CanonicalSSHPubKey(peer.key)
		if !ok {
			continue
		}
		managed[key] = true
		if len(managed) > 4096 {
			return 0, errors.New("combined managed SSH inventory capacity exceeded")
		}
		p, err := accessPolicy(ctx, tx, peer.token)
		if err != nil {
			return 0, err
		}
		if p.Status == "approved" {
			desired[key] = true
		}
	}
	pubs, revoked := []string{}, []string{}
	for key := range managed {
		if _, err := tx.ExecContext(ctx, `INSERT INTO managed_ssh_keys(public_key,desired) VALUES(?,?) ON CONFLICT(public_key) DO UPDATE SET desired=excluded.desired,updated_at=CURRENT_TIMESTAMP`, key, desired[key]); err != nil {
			return 0, err
		}
		if desired[key] {
			pubs = append(pubs, key)
		} else {
			revoked = append(revoked, key)
		}
	}
	// SQLite uses an immediate write transaction: all admission writers stay
	// serialized until the file is applied, avoiding a stale reconcile re-adding
	// a just-revoked key. On crash/SQL failure the durable ownership is retained
	// and a subsequent pass repeats the idempotent file operation.
	n, err := reconcileManagedAuthorizedKeys(path, target, pubs, revoked, true)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}
