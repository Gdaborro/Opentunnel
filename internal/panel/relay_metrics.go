package panel

import (
	"encoding/json"
	"time"

	"opentunnel/internal/metrics"
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
