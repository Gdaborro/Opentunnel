package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

type RuntimeStatus struct {
	Version               string                 `json:"version"`
	Edition               string                 `json:"client_edition"`
	LocalPreview          string                 `json:"unreleased_local_preview,omitempty"`
	Running               bool                   `json:"running"`
	PID                   int                    `json:"pid"`
	At                    int64                  `json:"at"`
	ProtectedScope        string                 `json:"protected_scope"`
	SOCKS                 string                 `json:"socks_listener"`
	HTTP                  string                 `json:"http_listener"`
	Pool                  string                 `json:"pool"`
	Node                  string                 `json:"node"`
	Authority             string                 `json:"authority"`
	Profile               string                 `json:"profile"`
	ChannelAuthentication bool                   `json:"channel_authentication_required"`
	Admission             string                 `json:"admission"`
	Failure               string                 `json:"failure_category"`
	Privacy               string                 `json:"telemetry"`
	UpdateChannel         string                 `json:"update_channel"`
	UpdateState           string                 `json:"update_state"`
	FreshnessExpires      int64                  `json:"signed_update_freshness_expires,omitempty"`
	RecoveryPending       bool                   `json:"browser_policy_cleanup_pending"`
	DirectBypass          []string               `json:"direct_bypass_hosts"`
	DirectBypassCount     uint64                 `json:"direct_bypass_requests"`
	OutsideScope          []string               `json:"outside_scope"`
	RetiredClients        int                    `json:"draining_clients"`
	ConnectionVerified    bool                   `json:"authenticated_activity_observed"`
	CarrierFailures       []CarrierFailureStatus `json:"carrier_failures"`
}

type CarrierFailureStatus struct {
	Carrier           string `json:"carrier"`
	Failure           string `json:"failure_category"`
	RetryAfterSeconds int64  `json:"retry_after_seconds"`
}

var directBypassCount atomic.Uint64

func NoteDirectBypass() { directBypassCount.Add(1) }

func (a *Adaptive) runtimeDetails() (profile, failure string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tierName(a.idx), a.lastFailure
}
func (a *Adaptive) noteRuntimeFailure(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastFailure = runtimeFailureCategory(err)
}
func runtimeFailureCategory(err error) string {
	if err == nil {
		return ""
	}
	var pending *PendingError
	var blocked *BlockedError
	var sshRejected *transport.SSHKeyRejectedError
	var unavailable *CarrierUnavailableError
	switch {
	case errors.As(err, &unavailable):
		return unavailable.Failure
	case errors.Is(err, ErrNetworkChanged):
		return "network-changed"
	case errors.As(err, &sshRejected):
		return "ssh-key-rejected"
	case errors.Is(err, ErrMuxCapacity):
		return "capacity"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.As(err, &pending):
		return "approval"
	case errors.As(err, &blocked):
		return "operator-policy"
	case isPinFailure(err):
		return "trust-verification"
	case isDNSError(err):
		return "entry-dns"
	default:
		return "connection-or-authority"
	}
}

func SaveRuntimeStatus(cfg *config.ClientConf, a *Adaptive, gateAdmission string, bypass map[string]bool, recoveryPending bool, running bool) error {
	s := RuntimeStatus{Version: version.Version, Edition: version.ClientEdition, LocalPreview: version.LocalPreview, Running: running, PID: os.Getpid(), At: time.Now().Unix(), ProtectedScope: "application HTTP/SOCKS proxy only; not a system-wide VPN", SOCKS: cfg.SOCKSAddr, HTTP: cfg.HTTPAddr, Pool: "default", Node: cfg.ServerAddr, ChannelAuthentication: cfg.RequireChannelAuth, Admission: gateAdmission, Privacy: cfg.Telemetry, UpdateChannel: cfg.UpdateChannel, RecoveryPending: recoveryPending, OutsideScope: []string{"applications ignoring HTTP/SOCKS proxy settings", "direct bypass hosts", "system-wide DNS/IPv6/UDP routing and kill switch"}}
	if s.Privacy == "" {
		s.Privacy = "full (existing fleet monitoring)"
	}
	if s.UpdateChannel == "" {
		s.UpdateChannel = "stable"
	}
	if cfg.Pool != nil {
		s.Pool = cfg.Pool.ID
		s.Authority = cfg.Pool.AuthorityID
		if cfg.PoolNode != nil {
			s.Node = cfg.PoolNode().ID
		}
	}
	if a != nil {
		a.mu.Lock()
		s.Profile, s.Failure = a.tierName(a.idx), a.lastFailure
		s.ConnectionVerified = !a.closed && !a.verifiedAt.IsZero()
		if cfg.Pool == nil && a.base.ServerAddr != "" {
			s.Node = a.base.ServerAddr
		}
		for carrier, failure := range a.tierFailures {
			retry := time.Time{}
			if carrier == "ws-tls" {
				retry = a.tcpRetryAt
			} else {
				for idx := len(profileOrder); idx < a.tierCount(); idx++ {
					if a.tierName(idx) == carrier {
						retry = a.tierCooldown[idx]
					}
				}
				if carrier == SshTierName && a.sshCooldown.After(retry) {
					retry = a.sshCooldown
				}
			}
			s.CarrierFailures = append(s.CarrierFailures, CarrierFailureStatus{Carrier: carrier, Failure: failure, RetryAfterSeconds: max(0, int64(time.Until(retry).Seconds()))})
		}
		s.RetiredClients = len(a.retiredClients)
		if s.Admission == "" {
			s.Admission = a.lastAdmission
		}
		a.mu.Unlock()
	}
	if s.CarrierFailures == nil {
		s.CarrierFailures = []CarrierFailureStatus{}
	}
	sort.Slice(s.CarrierFailures, func(i, j int) bool { return s.CarrierFailures[i].Carrier < s.CarrierFailures[j].Carrier })
	for host := range bypass {
		s.DirectBypass = append(s.DirectBypass, host)
	}
	if s.DirectBypass == nil {
		s.DirectBypass = []string{}
	}
	s.DirectBypassCount = directBypassCount.Load()
	sort.Strings(s.DirectBypass)
	if s.Admission == "" {
		s.Admission = "not-yet-verified; listening does not imply approval"
	}
	status := CurrentUpdateStatus()
	s.UpdateState = status.State
	s.FreshnessExpires = status.ExpiresAt
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return privatefile.Write(filepath.Join(store.Dir, "runtime-status.json"), raw)
}

// ReadRuntimeStatus only reads a bounded private JSON status file. It never
// calls proxy recovery, reads private keys/tokens or opens an external socket.
func ReadRuntimeStatus() (RuntimeStatus, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	raw, err := privatefile.ReadOnly(filepath.Join(base, version.ProductName, "runtime-status.json"), 16<<10)
	var s RuntimeStatus
	if err != nil {
		return s, err
	}
	if serverpool.DecodeStrict(raw, &s) != nil || s.At < 1 || s.At > time.Now().Unix()+120 {
		return s, errors.New("runtime status invalid")
	}
	if time.Since(time.Unix(s.At, 0)) > 45*time.Second {
		s.Running = false
		s.Failure = "stale-status; no running-client proof"
	}
	return s, nil
}

// WatchNetworkChanges never changes proxy/DNS/routing state or operator trust.
// Stable interface-address changes retire warm pools; active streams retain
// their owners and new dials re-probe without waiting for a stale cooldown.
func (a *Adaptive) WatchNetworkChanges(ctx context.Context) {
	previous, err := networkAddressSet()
	if err != nil {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := networkAddressSet()
			if err != nil {
				continue
			}
			if current != previous {
				previous = current
				a.NetworkChanged()
			}
		}
	}
}

func networkAddressSet() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var addresses []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		list, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range list {
			addresses = append(addresses, iface.Name+"|"+addr.String())
		}
	}
	sort.Strings(addresses)
	raw, _ := json.Marshal(addresses)
	return string(raw), nil
}

func (a *Adaptive) NetworkChanged() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.sshCooldown = time.Time{}
	a.sshRejects = 0
	a.tierCooldown = nil
	a.failStreak = 0
	a.lastProbe = time.Time{}
	a.tcpRetryAt = time.Time{}
	a.tierFailures = nil
	a.lastFailure = "network-changed; re-verification pending"
	a.lastAdmission = ""
	a.hostile = false // re-probe strict pinned TCP on the changed network; trust is unchanged
	if a.auto {
		a.idx = 0
	}
	a.invalidateClientsLocked()
	selector := a.poolSelector
	setHostileMode(false)
	a.mu.Unlock()
	if selector != nil {
		selector.Invalidate()
	}
}
