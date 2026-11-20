package panel

import (
	"errors"
	"sync"
	"testing"
	"time"

	"opentunnel/internal/authority"
)

func centralPeer(t *testing.T, db *DB) (string, string, string) {
	t.Helper()
	if _, err := db.BindServerPoolAuthentication(syntheticEnrollmentPool, false, true); err != nil {
		t.Fatal(err)
	}
	token := accessPeer(t, db)
	pub := testKeyLine(t)
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=?,channel_seen=1,channel_epoch=auth_epoch,v5_seen=datetime('now') WHERE token=?`, pub, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO peer_enrollments(token,username,pool_id,public_key) VALUES(?,'',?,?)`, token, syntheticEnrollmentPool, pub); err != nil {
		t.Fatal(err)
	}
	return token, "epoch-a", pub
}

func centralRequest(t *testing.T, token, generation string, n int) authority.ReserveRequest {
	t.Helper()
	id, err := authority.NewReservationID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return authority.ReserveRequest{ID: id, Token: token, Generation: generation, Requested: n}
}

func TestCentralReservationIsIdempotentAndRefundIsNodeAndGrantBound(t *testing.T) {
	db := newTestDB(t)
	token, generation, _ := centralPeer(t, db)
	req := centralRequest(t, token, generation, 4096)
	first, err := db.ReserveNodeTraffic(t.Context(), "node-a", req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.ReserveNodeTraffic(t.Context(), "node-a", req)
	if err != nil || first.ID != second.ID || first.Bytes != second.Bytes || first.Day != second.Day || first.ReadyAt != second.ReadyAt {
		t.Fatal("lost acknowledgement double charged", err)
	}
	if _, err := db.ReserveNodeTraffic(t.Context(), "node-b", req); !errors.Is(err, authority.ErrDenied) {
		t.Fatal("another node reused operation ID", err)
	}
	settle := authority.Settlement{ID: req.ID, Token: token, Generation: generation, Refund: 1024}
	if err := db.SettleNodeTraffic(t.Context(), "node-b", settle); err == nil {
		t.Fatal("other node refunded grant")
	}
	if err := db.SettleNodeTraffic(t.Context(), "node-a", settle); err != nil {
		t.Fatal(err)
	}
	if err := db.SettleNodeTraffic(t.Context(), "node-a", settle); err != nil {
		t.Fatal("idempotent settlement failed", err)
	}
	settle.Refund++
	if err := db.SettleNodeTraffic(t.Context(), "node-a", settle); err == nil {
		t.Fatal("conflicting retry refunded twice")
	}
	p, err := db.AccessPolicy(token)
	if err != nil || p.UsedBytes != 3072 {
		t.Fatal("aggregate accounting incorrect", p.UsedBytes, err)
	}
	if _, err := db.ReserveNodeTraffic(t.Context(), "node-a", req); err == nil {
		t.Fatal("settled grant reused for new send")
	}
}

func TestCentralQuotaConcurrentNodesNeverExceedsTotal(t *testing.T) {
	db := newTestDB(t)
	token, generation, _ := centralPeer(t, db)
	if _, err := db.Exec(`UPDATE peers SET quota_bytes=16384 WHERE token=?`, token); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 16 {
		req := centralRequest(t, token, generation, 4096)
		wg.Go(func() { _, _ = db.ReserveNodeTraffic(t.Context(), []string{"node-a", "node-b"}[i%2], req) })
	}
	wg.Wait()
	p, err := db.AccessPolicy(token)
	if err != nil || p.UsedBytes != 16384 {
		t.Fatal("two nodes did not share a hard quota", p.UsedBytes, err)
	}
	var bytes int
	if err := db.QueryRow(`SELECT SUM(bytes) FROM authority_reservations`).Scan(&bytes); err != nil || bytes != 16384 {
		t.Fatal("quota journal mismatch", bytes, err)
	}
}

func TestCentralReservationWriteFaultRollsBackUsageAndGrant(t *testing.T) {
	db := newTestDB(t)
	token, generation, _ := centralPeer(t, db)
	if _, err := db.Exec(`CREATE TRIGGER deny_reservation BEFORE INSERT ON authority_reservations BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReserveNodeTraffic(t.Context(), "node-a", centralRequest(t, token, generation, 4096)); err == nil {
		t.Fatal("journal fault reported success")
	}
	p, err := db.AccessPolicy(token)
	if err != nil || p.UsedBytes != 0 {
		t.Fatal("failed reservation partly charged", err)
	}
}

func TestCentralRefundKeepsReservationDayAndRejectsRekey(t *testing.T) {
	db := newTestDB(t)
	token, generation, pub := centralPeer(t, db)
	req := centralRequest(t, token, generation, 4096)
	req.Ingress = "ssh"
	grant, err := db.ReserveNodeTraffic(t.Context(), "node-a", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE authority_reservations SET day='2000-01-01' WHERE id=?`, grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO daily_usage(token,day,up,down) VALUES(?,'2000-01-01',4096,0)`, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO ingress_usage(token,ingress,day,up,down) VALUES(?,'ssh','2000-01-01',4096,0)`, token); err != nil {
		t.Fatal(err)
	}
	if err := db.SettleNodeTraffic(t.Context(), "node-a", authority.Settlement{ID: grant.ID, Token: token, Generation: generation, Ingress: "ssh", Refund: 1024}); err != nil {
		t.Fatal(err)
	}
	var today int
	if err := db.QueryRow(`SELECT up FROM ingress_usage WHERE token=? AND ingress='ssh' AND day=?`, token, grant.Day).Scan(&today); err != nil || today != 4096 {
		t.Fatal("cross-midnight refund subtracted current day", today, err)
	}
	req = centralRequest(t, token, generation, 4096)
	grant, err = db.ReserveNodeTraffic(t.Context(), "node-a", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RekeyPeer(token, pub, testKeyLine(t)); err != nil {
		t.Fatal(err)
	}
	if err := db.SettleNodeTraffic(t.Context(), "node-a", authority.Settlement{ID: grant.ID, Token: token, Generation: generation, Refund: grant.Bytes}); err == nil {
		t.Fatal("old generation refunded replacement identity")
	}
}

func TestCentralRateBudgetSharedAcrossNodesAndRefundCannotReplenish(t *testing.T) {
	db := newTestDB(t)
	token, generation, _ := centralPeer(t, db)
	if _, err := db.Exec(`UPDATE peers SET max_bps=16384 WHERE token=?`, token); err != nil {
		t.Fatal(err)
	}
	grants := make([]int64, 0, 4)
	for i := range 4 {
		req := centralRequest(t, token, generation, 32768)
		grant, err := db.ReserveNodeTraffic(t.Context(), []string{"node-a", "node-b"}[i%2], req)
		if err != nil {
			break
		}
		grants = append(grants, grant.ReadyAt)
		if err := db.SettleNodeTraffic(t.Context(), []string{"node-a", "node-b"}[i%2], authority.Settlement{ID: grant.ID, Token: token, Generation: generation, Refund: grant.Bytes}); err != nil {
			t.Fatal(err)
		}
	}
	if len(grants) < 2 || grants[1]-grants[0] < int64(time.Second) {
		t.Fatal("independent nodes or refund reset aggregate rate", grants)
	}
}
