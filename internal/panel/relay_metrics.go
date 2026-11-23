package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"opentunnel/internal/metrics"
	"opentunnel/internal/serverpool"
)

// The split panel process cannot read the relay's process-local counters.
// A local DB heartbeat makes that boundary explicit and marks stale data.
func (db *DB) RecordRelayMetrics(sample metrics.Snapshot) error {
	raw, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO relay_metrics(id,snapshot,at) VALUES(1,?,datetime('now')) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot,at=excluded.at`, string(raw))
	return err
}

type NodeMetrics struct {
	Node       string           `json:"node"`
	Online     bool             `json:"online"`
	AgeSeconds int64            `json:"age_seconds"`
	Snapshot   metrics.Snapshot `json:"snapshot"`
}

func (db *DB) NodeMetrics(parent context.Context) ([]NodeMetrics, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `SELECT node_id,snapshot,CAST(at AS TEXT) FROM authority_node_metrics ORDER BY node_id LIMIT 17`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []NodeMetrics{}
	for rows.Next() {
		var node, raw, stamp string
		if err := rows.Scan(&node, &raw, &stamp); err != nil {
			return nil, err
		}
		var item NodeMetrics
		item.Node = node
		if len(raw) > 4096 || serverpool.DecodeStrict([]byte(raw), &item.Snapshot) != nil {
			return nil, fmt.Errorf("invalid node diagnostics")
		}
		at, err := time.Parse("2006-01-02 15:04:05", stamp)
		if err != nil {
			return nil, err
		}
		item.AgeSeconds = int64(time.Since(at).Seconds())
		item.Online = item.AgeSeconds >= 0 && item.AgeSeconds < 30
		list = append(list, item)
		if len(list) > 16 {
			return nil, fmt.Errorf("node diagnostics exceeds capacity")
		}
	}
	return list, rows.Err()
}
func (db *DB) RelayMetrics() (metrics.Snapshot, time.Time, error) {
	var sample metrics.Snapshot
	var raw, at string
	err := db.QueryRow(`SELECT snapshot,CAST(at AS TEXT) FROM relay_metrics WHERE id=1`).Scan(&raw, &at)
	if err != nil {
		return sample, time.Time{}, err
	}
	if err := json.Unmarshal([]byte(raw), &sample); err != nil {
		return sample, time.Time{}, err
	}
	stamp, err := time.Parse("2006-01-02 15:04:05", at)
	return sample, stamp, err
}
