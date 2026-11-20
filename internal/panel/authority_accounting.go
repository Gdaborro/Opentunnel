package panel

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"opentunnel/internal/access"
	"opentunnel/internal/authority"
)

// ReserveNodeTraffic accounts a chunk exactly once across all relay hosts.
// Unknown/lost acknowledgements are conservatively charged. Unsettled records
// are never refunded automatically at expiry or when a node disappears.
func (db *DB) ReserveNodeTraffic(parent context.Context, node string, req authority.ReserveRequest) (access.Reservation, error) {
	now := time.Now()
	if !authority.ValidNodeID(node) || req.Validate(now) != nil {
		return access.Reservation{}, authority.ErrDenied
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	release, err := db.accountSlot(ctx)
	if err != nil {
		return access.Reservation{}, err
	}
	defer release()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return access.Reservation{}, err
	}
	defer tx.Rollback()
	var storedNode, token, generation, ingress string
	var requested int
	var down, settled bool
	r := access.Reservation{ID: req.ID}
	err = tx.QueryRowContext(ctx, `SELECT node_id,token,generation,ingress,down,requested,bytes,day,ready_at,settled FROM authority_reservations WHERE id=?`, req.ID).
		Scan(&storedNode, &token, &generation, &ingress, &down, &requested, &r.Bytes, &r.Day, &r.ReadyAt, &settled)
	if err == nil {
		if storedNode != node || token != req.Token || generation != req.Generation || ingress != req.Ingress || down != req.Down || requested != req.Requested || settled {
			return access.Reservation{}, authority.ErrDenied
		}
		p, err := accessPolicy(ctx, tx, req.Token)
		if err != nil || p.Generation != req.Generation || p.Status != "approved" || !p.ChannelVerified || !p.ChannelRequired || (p.KillSwitch && !p.KillAllowed) {
			return access.Reservation{}, authority.ErrDenied
		}
		r.DelayNs = max(int64(0), r.ReadyAt-time.Now().UnixNano())
		return r, tx.Commit() // retransmit the same grant, never charge twice
	}
	if err != sql.ErrNoRows {
		return access.Reservation{}, err
	}
	// The request's time window is shorter than journal retention. Once old
	// records are pruned their IDs have expired and cannot reserve again.
	if _, err := tx.ExecContext(ctx, `DELETE FROM authority_reservations WHERE (settled=0 AND created_at<?) OR (settled=1 AND created_at<?)`, now.Add(-authority.ReservationRetention).Unix(), now.Add(-authority.SettledRetention).Unix()); err != nil {
		return access.Reservation{}, err
	}
	var total, perNode, outstanding int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(node_id=?),0),COALESCE(SUM(token=? AND settled=0),0) FROM authority_reservations`, node, req.Token).Scan(&total, &perNode, &outstanding); err != nil {
		return access.Reservation{}, err
	}
	if total >= authority.MaxReservations || perNode >= authority.MaxNodeReservations || outstanding >= authority.MaxPeerOutstanding {
		return access.Reservation{}, errors.New("authority reservation capacity reached")
	}
	p, err := accessPolicy(ctx, tx, req.Token)
	if err != nil {
		return access.Reservation{}, err
	}
	if p.Generation != req.Generation || p.Status != "approved" || !p.ChannelRequired || !p.ChannelVerified || (p.KillSwitch && !p.KillAllowed) {
		return access.Reservation{}, authority.ErrDenied
	}
	n := req.Requested
	if p.QuotaBytes > 0 && int64(n) > p.QuotaBytes-p.UsedBytes {
		n = int(max(int64(0), p.QuotaBytes-p.UsedBytes)) // conversion only after a bounded comparison
	}
	sshBps := p.SSHMaxBps
	if req.Ingress == "ssh" && p.SSHDailyBytes > 0 && p.SSHUsedBytes >= p.SSHDailyBytes {
		sshBps = lowerPositiveRate(sshBps, p.SSHTrickleBps)
	}
	// Bound a low-rate reservation to two seconds' service so a caller cannot
	// hold arbitrarily distant grants or force an unbounded waiting queue.
	for _, bps := range []int64{p.MaxBps, func() int64 {
		if req.Ingress == "ssh" {
			return sshBps
		}
		return 0
	}()} {
		if bps > 0 && bps < 32768 {
			n = min(n, int(bps*2))
		}
	}
	if n < 1 {
		return access.Reservation{}, authority.ErrDenied
	}
	ready := now.UnixNano()
	for _, limit := range []struct {
		scope string
		bps   int64
	}{{"device", p.MaxBps}, {"ssh", func() int64 {
		if req.Ingress == "ssh" {
			return sshBps
		}
		return 0
	}()}} {
		if limit.bps <= 0 {
			continue
		}
		at, err := reserveAggregateRate(ctx, tx, req.Token, req.Generation, limit.scope, limit.bps, n, now)
		if err != nil {
			return access.Reservation{}, err
		}
		ready = max(ready, at)
	}
	up, downBytes := n, 0
	if req.Down {
		up, downBytes = 0, n
	}
	if err := tx.QueryRowContext(ctx, `SELECT date('now')`).Scan(&r.Day); err != nil {
		return access.Reservation{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE peers SET bytes_up=bytes_up+?,bytes_down=bytes_down+?,last_seen=datetime('now') WHERE token=? AND auth_epoch=? AND status IN ('approved','kicked') AND (COALESCE(quota_bytes,0)=0 OR bytes_up+bytes_down+?<=quota_bytes)`, up, downBytes, req.Token, req.Generation, n)
	if err != nil {
		return access.Reservation{}, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return access.Reservation{}, authority.ErrDenied
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO daily_usage(token,day,up,down) VALUES(?,?,?,?) ON CONFLICT(token,day) DO UPDATE SET up=up+excluded.up,down=down+excluded.down`, req.Token, r.Day, up, downBytes); err != nil {
		return access.Reservation{}, err
	}
	if req.Ingress != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ingress_usage(token,ingress,day,up,down) VALUES(?,?,?,?,?) ON CONFLICT(token,ingress,day) DO UPDATE SET up=up+excluded.up,down=down+excluded.down`, req.Token, req.Ingress, r.Day, up, downBytes); err != nil {
			return access.Reservation{}, err
		}
	}
	r.Bytes, r.ReadyAt = n, ready
	r.DelayNs = max(int64(0), ready-now.UnixNano())
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_reservations(id,node_id,token,generation,ingress,down,requested,bytes,day,ready_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, req.ID, node, req.Token, req.Generation, req.Ingress, req.Down, req.Requested, r.Bytes, r.Day, r.ReadyAt, now.Unix()); err != nil {
		return access.Reservation{}, err
	}
	if err := tx.Commit(); err != nil {
		return access.Reservation{}, err
	}
	return r, nil
}

func lowerPositiveRate(a, b int64) int64 {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	return min(a, b)
}

// A durable shared virtual service time covers both directions and all nodes.
// A 64 KiB burst is the only unpaced allowance. Refunds do not replenish this
// rate budget, preventing a reserve/refund loop from buying unlimited bursts.
func reserveAggregateRate(ctx context.Context, tx *sql.Tx, token, generation, scope string, bps int64, n int, now time.Time) (int64, error) {
	var oldGeneration string
	var next int64
	err := tx.QueryRowContext(ctx, `SELECT generation,next_ns FROM authority_rates WHERE token=? AND scope=?`, token, scope).Scan(&oldGeneration, &next)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	burstBytes := int64(65536)
	if bps < burstBytes/2 {
		burstBytes = bps * 2
	} // avoid overflow for externally stored limits
	burstNs := burstBytes * int64(time.Second) / bps
	if err == sql.ErrNoRows || oldGeneration != generation {
		next = now.UnixNano() - burstNs
	}
	next = max(next, now.UnixNano()-burstNs)
	serviceNs := max(int64(1), int64(n)*int64(time.Second)/bps)
	next += serviceNs
	ready := max(now.UnixNano(), next)
	if ready-now.UnixNano() > int64(4*time.Second) {
		return 0, errors.New("aggregate authority pacing capacity reached")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authority_rates(token,scope,generation,next_ns) VALUES(?,?,?,?) ON CONFLICT(token,scope) DO UPDATE SET generation=excluded.generation,next_ns=excluded.next_ns`, token, scope, generation, next); err != nil {
		return 0, err
	}
	return ready, nil
}

// SettleNodeTraffic trusts only the recorded grant, not a supplied day/size.
// Retries are idempotent. Changed generation, another node, conflicting refund
// or an expired/unknown grant can never subtract another identity's usage.
func (db *DB) SettleNodeTraffic(parent context.Context, node string, req authority.Settlement) error {
	if !authority.ValidNodeID(node) || !authority.ValidToken(req.Token) || !authority.ValidGeneration(req.Generation) || req.Refund < 0 {
		return authority.ErrDenied
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
	var storedNode, token, generation, ingress, day string
	var down, settled bool
	var bytes, previousRefund int
	var createdAt int64
	if err := tx.QueryRowContext(ctx, `SELECT node_id,token,generation,ingress,down,bytes,day,settled,refund,created_at FROM authority_reservations WHERE id=?`, req.ID).Scan(&storedNode, &token, &generation, &ingress, &down, &bytes, &day, &settled, &previousRefund, &createdAt); err != nil {
		return err
	}
	if storedNode != node || token != req.Token || generation != req.Generation || ingress != req.Ingress || down != req.Down || req.Refund > bytes {
		return authority.ErrDenied
	}
	if settled {
		if previousRefund != req.Refund {
			return authority.ErrDenied
		}
		return tx.Commit()
	}
	if createdAt < time.Now().Add(-authority.ReservationRetention).Unix() {
		return authority.ErrDenied
	}
	if req.Refund > 0 {
		column := "up"
		if down {
			column = "down"
		}
		result, err := tx.ExecContext(ctx, `UPDATE peers SET bytes_`+column+`=MAX(0,bytes_`+column+`-?) WHERE token=? AND auth_epoch=?`, req.Refund, token, generation)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return authority.ErrDenied
		}
		if _, err := tx.ExecContext(ctx, `UPDATE daily_usage SET `+column+`=MAX(0,`+column+`-?) WHERE token=? AND day=?`, req.Refund, token, day); err != nil {
			return err
		}
		if ingress != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE ingress_usage SET `+column+`=MAX(0,`+column+`-?) WHERE token=? AND ingress=? AND day=?`, req.Refund, token, ingress, day); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE authority_reservations SET settled=1,refund=? WHERE id=?`, req.Refund, req.ID); err != nil {
		return err
	}
	return tx.Commit()
}
