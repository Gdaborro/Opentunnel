package panel

import (
	"path/filepath"
	"testing"
)

func TestChannelMigrationRefusesUnverifiedDevicesAndBackupPreservesPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.db")
	db, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	info, err := db.BindServerPool(syntheticEnrollmentPool, false)
	if err != nil {
		t.Fatal(err)
	}
	token := accessPeer(t, db)
	key := testKeyLine(t)
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=? WHERE token=?`, key, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peer_enrollments(token,username,pool_id,public_key) VALUES(?,'',?,?)`, token, info.PoolID, key); err != nil {
		t.Fatal(err)
	}
	if err := db.EnablePoolChannelAuthentication(t.Context(), info.PoolID, info.AuthorityID); err == nil {
		t.Fatal("unverified approved fleet migrated")
	}
	if err := db.CommitAuthentication(token, "epoch-a", key, true); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "pre-enforcement.db")
	if err := db.BackupDatabase(t.Context(), backup); err != nil {
		t.Fatal(err)
	}
	if err := db.BackupDatabase(t.Context(), backup); err == nil {
		t.Fatal("database backup overwritten")
	}
	if err := db.EnablePoolChannelAuthentication(t.Context(), info.PoolID, info.AuthorityID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BindServerPool(info.PoolID, false); err == nil {
		t.Fatal("legacy startup silently removed migrated enforcement")
	}
	copy, err := Open(backup, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if _, err := copy.BindServerPool(info.PoolID, false); err != nil {
		t.Fatal("backup did not preserve pre-enforcement authority", err)
	}
	p, err := copy.AccessPolicy(token)
	if err != nil || !p.ChannelSeen || p.PublicKey != key || p.Generation != "epoch-a" {
		t.Fatal("backup lost existing identity/canary latch", err)
	}
}

func TestChannelMigrationAuditFaultRollsBackEnforcement(t *testing.T) {
	db := newTestDB(t)
	info, err := db.BindServerPool(syntheticEnrollmentPool, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER deny_migration_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.EnablePoolChannelAuthentication(t.Context(), info.PoolID, info.AuthorityID); err == nil {
		t.Fatal("audit fault reported migration success")
	}
	if _, err := db.BindServerPool(info.PoolID, false); err != nil {
		t.Fatal("fault partly changed authentication policy", err)
	}
}
