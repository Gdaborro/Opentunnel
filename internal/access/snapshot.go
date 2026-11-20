// Package access defines the relay's control-plane policy snapshot. Keeping
// this contract independent of SQL and transports lets every carrier enforce
// the same admission and resource policy.
package access

// Snapshot is one consistent view of a device and the operator's policy.
// Status is the effective verdict, including expiry, identity bans, schedules
// and quotas. An error reading a snapshot must never be treated as approval.
type Snapshot struct {
	Status          string `json:"status"`
	Reason          string `json:"reason"`
	Expires         string `json:"expires"`
	PublicKey       string `json:"public_key"`
	Generation      string `json:"generation"`
	PoolID          string `json:"pool_id"`
	AuthorityID     string `json:"authority_id"`
	Enrolled        bool   `json:"enrolled"`
	V5Seen          bool   `json:"v5_seen"`
	ChannelSeen     bool   `json:"channel_seen"`
	ChannelRequired bool   `json:"channel_required"`
	ChannelVerified bool   `json:"channel_verified_current_identity"`
	MaxBps          int64  `json:"max_bps"`
	QuotaBytes      int64  `json:"quota_bytes"`
	UsedBytes       int64  `json:"used_bytes"`
	KillSwitch      bool   `json:"kill_switch"`
	KillAllowed     bool   `json:"kill_allowed"`
	KillReason      string `json:"kill_reason"`
	SSHMaxBps       int64  `json:"ssh_max_bps"`
	SSHDailyBytes   int64  `json:"ssh_daily_bytes"`
	SSHTrickleBps   int64  `json:"ssh_trickle_bps"`
	SSHUsedBytes    int64  `json:"ssh_used_bytes"`
	TelemetryMode   string `json:"telemetry_mode"`
}

// Reservation fixes the accounting day at reservation time. A slow write
// refunded after UTC midnight must not subtract another day's usage.
type Reservation struct {
	ID      string `json:"id,omitempty"`
	Bytes   int    `json:"bytes"`
	Day     string `json:"day"`
	ReadyAt int64  `json:"ready_at,omitempty"` // central aggregate pacing grant; Unix nanoseconds
	DelayNs int64  `json:"delay_ns,omitempty"` // authoritative wait avoids relying on relay wall-clock equality
}
