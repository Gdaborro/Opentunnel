// Package authority defines the narrow, mutually authenticated relay API.
// Relay nodes never receive administrator credentials, password hashes or a
// database copy. A node is trusted to relay/account traffic honestly; this API
// cannot stop a compromised relay host from sending its own Internet traffic.
package authority

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"opentunnel/internal/access"
	"opentunnel/internal/metrics"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

const APIPath = "/internal/otu-authority/v1/"
const MaxBody = 16 << 10
const MaxResponse = 64 << 10
const ReservationWindow = 5 * time.Minute
const ReservationRetention = 15 * time.Minute
const SettledRetention = 6 * time.Minute
const MaxReservations = 65536
const MaxNodeReservations = 8192
const MaxPeerOutstanding = 64

// Bound per-operation accounting metadata as well as unresolved grants.

var ErrUnavailable = errors.New("approval/accounting authority unavailable; traffic denied")
var ErrDenied = errors.New("approval/accounting authority denied request")

type Node struct {
	ID   string   `json:"id"`
	Pins []string `json:"pins"` // independently provisioned node TLS public-key pins
}

type Nodes struct {
	Nodes []Node `json:"nodes"`
}

func ValidNodeID(id string) bool {
	if len(id) < 1 || len(id) > 48 {
		return false
	}
	for _, r := range id {
		if r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func (n Nodes) Validate() error {
	if len(n.Nodes) < 1 || len(n.Nodes) > serverpool.MaxNodes {
		return errors.New("authority needs 1..16 explicit nodes")
	}
	ids, pins := map[string]bool{}, map[string]bool{}
	for _, node := range n.Nodes {
		if !ValidNodeID(node.ID) || ids[node.ID] || len(node.Pins) < 1 || len(node.Pins) > 2 {
			return errors.New("invalid authority node identity or rotation set")
		}
		ids[node.ID] = true
		for _, pin := range node.Pins {
			if !serverpool.ValidID(pin) || pins[pin] {
				return errors.New("authority node credentials must be valid and distinct between nodes")
			}
			pins[pin] = true
		}
	}
	return nil
}

type TokenRequest struct {
	Token string `json:"token"`
}
type AuthRequest struct {
	Token        string `json:"token"`
	Generation   string `json:"generation"`
	PublicKey    string `json:"public_key"`
	ChannelBound bool   `json:"channel_bound"`
}
type BlockRequest struct {
	Domain string `json:"domain"`
}
type BlockResponse struct {
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason"`
}
type ReserveRequest struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	Generation string `json:"generation"`
	Ingress    string `json:"ingress"`
	Down       bool   `json:"down"`
	Requested  int    `json:"requested"`
}

// Settlement is an explicit wire struct: no field aliases, nested arbitrary
// JSON, trusted refund counts or caller-supplied accounting dates.
type Settlement struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	Generation string `json:"generation"`
	Ingress    string `json:"ingress"`
	Down       bool   `json:"down"`
	Refund     int    `json:"refund"`
}
type ControlRequest struct {
	Token      string               `json:"token"`
	Generation string               `json:"generation"`
	PublicKey  string               `json:"public_key"`
	Request    protocol.CtrlRequest `json:"request"`
}
type PeerIPRequest struct {
	Token      string `json:"token"`
	Generation string `json:"generation"`
	PublicKey  string `json:"public_key"`
	IP         string `json:"ip"`
}
type VisitRequest struct {
	Token      string `json:"token"`
	Generation string `json:"generation"`
	PublicKey  string `json:"public_key"`
	Domain     string `json:"domain"`
}
type EventRequest struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
}
type SettingRequest struct {
	Key string `json:"key"`
}
type SettingResponse struct {
	Value string `json:"value"`
}
type OK struct {
	OK bool `json:"ok"`
}

type Store interface {
	AccessPolicy(string) (access.Snapshot, error)
	CheckBlocked(string) (bool, string, error)
	CommitAuthentication(string, string, string, bool) error
	ReserveNodeTraffic(context.Context, string, ReserveRequest) (access.Reservation, error)
	SettleNodeTraffic(context.Context, string, Settlement) error
	ControlBound(context.Context, ControlRequest) (protocol.CtrlResponse, error)
	SetPeerIPBound(context.Context, PeerIPRequest) error
	RecordVisitBound(context.Context, VisitRequest) error
	RecordNodeEvent(context.Context, string, EventRequest) error
	RecordNodeMetrics(context.Context, string, metrics.Snapshot) error
	AuthoritySetting(context.Context, string) (string, error)
}

func ValidToken(token string) bool {
	if len(token) < 16 || len(token) > 128 {
		return false
	}
	for _, r := range token {
		if r != '-' && r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func ValidGeneration(generation string) bool {
	if len(generation) < 1 || len(generation) > 128 {
		return false
	}
	for _, r := range generation {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func ReservationTime(id string) (time.Time, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 2 || len(parts[1]) != 32 {
		return time.Time{}, errors.New("invalid reservation ID")
	}
	for _, c := range parts[1] {
		if c != '-' && c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return time.Time{}, errors.New("invalid reservation nonce")
		}
	}
	at, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || at <= 0 || strconv.FormatInt(at, 10) != parts[0] {
		return time.Time{}, errors.New("invalid reservation time")
	}
	return time.Unix(at, 0), nil
}

func (r ReserveRequest) Validate(now time.Time) error {
	at, err := ReservationTime(r.ID)
	if err != nil || at.After(now.Add(30*time.Second)) || now.Sub(at) > ReservationWindow || !ValidToken(r.Token) || !ValidGeneration(r.Generation) || r.Requested < 1 || r.Requested > 65535 || (r.Ingress != "" && r.Ingress != "ssh" && r.Ingress != "carrier") {
		return errors.New("invalid or expired traffic reservation")
	}
	return nil
}
