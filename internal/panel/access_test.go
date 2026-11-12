package panel

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func accessPeer(t *testing.T, db *DB) string {
	t.Helper()
	const token = "synthetic-access-token-123456"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,auth_epoch)
		VALUES(?,'fixture','approved',datetime('now'),datetime('now'),'epoch-a')`, token); err != nil {
		t.Fatal(err)
	}
	return token
}

func TestAccessPolicyFailsClosedOnSQLFailure(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	if p, err := db.AccessPolicy(token); err != nil || p.Status != "approved" {
		t.Fatalf("baseline: %+v %v", p, err)
	}
	_ = db.Close()
	if _, _, _, err := db.CheckToken(token); err == nil {
		t.Fatal("SQL failure was hidden as a normal pending verdict")
	}
	if _, err := db.AccessPolicy(token); err == nil {
		t.Fatal("closed database produced a policy snapshot")
	}
}

func TestAccessPolicyExpiryAndMalformedState(t *testing.T) {
	for _, tc := range []struct {
		name, update, status string
		wantErr              bool
	}{
		{"pending", "status='pending'", "pending", false},
		{"expired", "status='expired'", "expired", false},
		{"time expiry", "expires_at=datetime('now','-1 minute')", "expired", false},
		{"bad expiry", "expires_at='not-a-time'", "", true},
		{"bad schedule", "schedule='not-a-schedule'", "", true},
		{"negative quota", "quota_bytes=-1", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			token := accessPeer(t, db)
			if _, err := db.Exec(`UPDATE peers SET `+tc.update+` WHERE token=?`, token); err != nil {
				t.Fatal(err)
			}
			p, err := db.AccessPolicy(token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("invalid state accepted: %+v", p)
				}
				return
			}
			if err != nil || p.Status != tc.status {
				t.Fatalf("verdict=%q error=%v", p.Status, err)
			}
		})
	}
}

func TestPolicyCachesAreDatabaseScoped(t *testing.T) {
	a, b := newTestDB(t), newTestDB(t)
	a.SetKillSwitch(true)
	a.SetSetting("ssh_tier_max_bps", "12345")
	a.SetCategoryEnabled("social", true)
	if !a.KillSwitch() || b.KillSwitch() {
		t.Fatal("kill-switch cache crossed databases")
	}
	if a.IsBlocked("facebook.com") == b.IsBlocked("facebook.com") {
		t.Fatal("block cache crossed databases")
	}
	maxA, _, _ := a.SSHTierLimits()
	maxB, _, _ := b.SSHTierLimits()
	if maxA != 12345 || maxB != 0 {
		t.Fatalf("SSH caches crossed databases: %d, %d", maxA, maxB)
	}
}

func TestConcurrentTrafficReservationsCannotOvershootQuota(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	if _, err := db.Exec(`UPDATE peers SET quota_bytes=5000 WHERE token=?`, token); err != nil {
		t.Fatal(err)
	}
	var total atomic.Int64
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := db.ReserveTraffic(context.Background(), token, "epoch-a", "ssh", i%2 == 0, 1024)
			if err == nil {
				total.Add(int64(r.Bytes))
			}
		}()
	}
	wg.Wait()
	if total.Load() != 5000 {
		t.Fatalf("reserved=%d want 5000", total.Load())
	}
	p, err := db.AccessPolicy(token)
	if err != nil || p.Status != "kicked" || p.UsedBytes != 5000 || p.SSHUsedBytes != 5000 {
		t.Fatalf("policy=%+v err=%v", p, err)
	}
}

func TestTrafficUsagePersistsAndRefundIsGenerationBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounting.db")
	db, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	token := accessPeer(t, db)
	r, err := db.ReserveTraffic(context.Background(), token, "epoch-a", "ssh", false, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RefundTraffic(context.Background(), token, "epoch-a", "ssh", false, r, 1024); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	db, err = Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.AccessPolicy(token)
	if err != nil || p.UsedBytes != 3072 || p.SSHUsedBytes != 3072 {
		t.Fatalf("persisted policy=%+v err=%v", p, err)
	}
	if _, err := db.Exec(`UPDATE peers SET auth_epoch='replacement',bytes_up=777 WHERE token=?`, token); err != nil {
		t.Fatal(err)
	}
	if err := db.RefundTraffic(context.Background(), token, "epoch-a", "ssh", false, r, 100); err == nil {
		t.Fatal("old stream refunded a replacement identity")
	}
	p, _ = db.AccessPolicy(token)
	if p.UsedBytes != 777 {
		t.Fatal("replacement usage was changed by old refund")
	}
}

func TestAccountingWaitHonorsCancellation(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	release, err := db.accountSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.ReserveTraffic(ctx, token, "epoch-a", "ssh", false, 100); err == nil {
		t.Fatal("cancelled accounting request waited or succeeded")
	}
}

func TestReservationRejectsPolicyChangeBeforeCachedWriterRefresh(t *testing.T) {
	for _, change := range []string{"pending", "kick", "ban", "kill", "schedule"} {
		t.Run(change, func(t *testing.T) {
			db := newTestDB(t)
			token := accessPeer(t, db)
			switch change {
			case "pending":
				db.Exec(`UPDATE peers SET status='pending' WHERE token=?`, token)
			case "kick":
				db.Exec(`UPDATE peers SET status='kicked',kick_expires=datetime('now','+1 minute') WHERE token=?`, token)
			case "ban":
				db.Exec(`UPDATE peers SET status='banned' WHERE token=?`, token)
			case "kill":
				db.SetKillSwitch(true)
			case "schedule":
				db.Exec(`UPDATE peers SET schedule='0000-0000' WHERE token=?`, token)
			}
			if _, err := db.ReserveTraffic(t.Context(), token, "epoch-a", "", false, 100); err == nil {
				t.Fatal("cached writer reserved traffic after authoritative denial")
			}
		})
	}
}

func TestConcurrentRelayAndPanelMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	start := make(chan struct{})
	results := make(chan error, 4)
	for range 4 {
		go func() {
			<-start
			db, err := Open(path, 14)
			if err == nil {
				if closeErr := db.Close(); closeErr != nil {
					err = fmt.Errorf("close: %w", closeErr)
				}
			} else {
				err = fmt.Errorf("open: %w", err)
			}
			results <- err
		}()
	}
	close(start)
	for range 4 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent startup failed: %v", err)
		}
	}
}

func TestWriterTransactionLocksBeforeReadingItsSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer-snapshot.db")
	a, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	token := accessPeer(t, a)
	b, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tx, err := a.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// With a deferred transaction, another process can commit before this
	// first policy read. Writer transactions must reserve the lock at BEGIN.
	other, err := b.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// Keep the synthetic competitor's SQLite wait below the owner's lifetime.
	// Some driver busy waits outlast a canceled query context.
	if _, err := other.ExecContext(t.Context(), `PRAGMA busy_timeout=100`); err != nil {
		t.Fatal(err)
	}
	if _, err := other.ExecContext(t.Context(), `UPDATE peers SET last_ip='192.0.2.1' WHERE token=?`, token); err == nil {
		t.Fatal("competing writer committed before the transaction's snapshot lock")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.ExecContext(t.Context(), `UPDATE peers SET last_ip='192.0.2.1' WHERE token=?`, token); err != nil {
		t.Fatal("writer lock was not released", err)
	}
}

func TestReservationsSurviveIndependentMetadataWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata-contention.db")
	a, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	token := accessPeer(t, a)
	b, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	metadataDone := make(chan error, 1)
	go func() {
		for range 100 {
			if _, err := b.ExecContext(ctx, `UPDATE peers SET last_seen=datetime('now'),last_ip='192.0.2.2' WHERE token=?`, token); err != nil {
				metadataDone <- err
				return
			}
		}
		metadataDone <- nil
	}()
	for range 100 {
		r, err := a.ReserveTraffic(ctx, token, "epoch-a", "carrier", true, 1024)
		if err != nil || r.Bytes != 1024 {
			t.Fatal("independent metadata writer interrupted admitted payload reservation", err)
		}
	}
	if err := <-metadataDone; err != nil {
		t.Fatal(err)
	}
	p, err := a.AccessPolicy(token)
	if err != nil || p.UsedBytes != 100*1024 {
		t.Fatal("contention corrupted reservation accounting", err)
	}
}

func BenchmarkTrafficReservation(b *testing.B) {
	db, err := Open(filepath.Join(b.TempDir(), "usage.db"), 14)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,auth_epoch) VALUES('bench','fixture','approved',datetime('now'),datetime('now'),'bench')`); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(32 << 10)
	b.ResetTimer()
	for range b.N {
		if _, err := db.ReserveTraffic(context.Background(), "bench", "bench", "ssh", false, 32<<10); err != nil {
			b.Fatal(err)
		}
	}
}
