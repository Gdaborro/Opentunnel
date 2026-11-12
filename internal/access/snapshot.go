// Package access defines the relay's control-plane policy snapshot. Keeping
// this contract independent of SQL and transports lets every carrier enforce
// the same admission and resource policy.
package access

// Snapshot is one consistent view of a device and the operator's policy.
// Status is the effective verdict, including expiry, identity bans, schedules
// and quotas. An error reading a snapshot must never be treated as approval.
type Snapshot struct {
	Status, Reason, Expires string
	PublicKey, Generation   string
	V5Seen                  bool
	MaxBps, QuotaBytes      int64
	UsedBytes               int64
	KillSwitch              bool
	KillAllowed             bool
	KillReason              string
	SSHMaxBps               int64
	SSHDailyBytes           int64
	SSHTrickleBps           int64
	SSHUsedBytes            int64
}

// Reservation fixes the accounting day at reservation time. A slow write
// refunded after UTC midnight must not subtract another day's usage.
type Reservation struct {
	Bytes int
	Day   string
}
