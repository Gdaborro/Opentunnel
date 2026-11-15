// Package serverpool validates explicitly trusted, operator-signed server pools.
// It is not a public directory or a scanner for arbitrary tunnel servers.
package serverpool

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	ProfileVersion = 1
	MaxNodes       = 16
	MaxProfileSize = 64 << 10
	MaxValidity    = 90 * 24 * time.Hour
	InfoPath       = "/api/token/server-info"
)

type Node struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Address      string   `json:"address"`                // HTTP authority and TLS name, always host:port
	DialAddress  string   `json:"dial_address,omitempty"` // optional literal IP:port; never changes trust/authority
	Pins         []string `json:"pins"`
	WSPath       string   `json:"ws_path"`
	InnerTLSPins []string `json:"inner_tls_pins,omitempty"`
}

// A pool is one approval/accounting authority, not just a geographical list.
// Independent operators must have different keys/IDs and enrollments.
type Profile struct {
	Version          int    `json:"version"`
	ID               string `json:"id"`           // SHA256 of the operator's Ed25519 public key
	AuthorityID      string `json:"authority_id"` // immutable ID of the shared approval/accounting database
	Name             string `json:"name"`
	OperatorKey      string `json:"operator_key"`
	IssuedAt         int64  `json:"issued_at"`
	ExpiresAt        int64  `json:"expires_at"`
	LoginRequired    bool   `json:"login_required"`
	ApprovalRequired bool   `json:"approval_required"`
	Nodes            []Node `json:"nodes"`
	Signature        string `json:"signature,omitempty"`
}

// Info is fetched without credentials over a node's pinned TLS connection.
type Info struct {
	Version          int    `json:"version"`
	PoolID           string `json:"pool_id"`
	AuthorityID      string `json:"authority_id"`
	LoginRequired    bool   `json:"login_required"`
	ApprovalRequired bool   `json:"approval_required"`
}

func OperatorID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func ValidID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32 && strings.ToLower(id) == id
}

func cleanLabel(s string, max int) bool {
	if s == "" || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

func validNodeID(id string) bool {
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

func validHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	if host == "" || len(host) > 253 || strings.ToLower(host) != host {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	return true
}

func validEndpoint(addr string, literalOnly bool) bool {
	host, port, err := net.SplitHostPort(addr)
	n, nerr := strconv.Atoi(port)
	if err != nil || nerr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || !validHost(host) || net.JoinHostPort(host, port) != addr {
		return false
	}
	if literalOnly {
		_, err = netip.ParseAddr(host)
		return err == nil
	}
	return true
}

func validPins(pins []string, required bool) bool {
	if len(pins) > 8 || (required && len(pins) == 0) {
		return false
	}
	seen := map[string]bool{}
	for _, pin := range pins {
		if !ValidID(pin) || seen[pin] {
			return false
		}
		seen[pin] = true
	}
	return true
}

func (p Profile) Validate(now time.Time) error {
	pub, err := base64.StdEncoding.DecodeString(p.OperatorKey)
	if p.Version != ProfileVersion || err != nil || len(pub) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(pub) != p.OperatorKey || p.ID != OperatorID(pub) || !ValidID(p.AuthorityID) || !cleanLabel(p.Name, 80) || !p.ApprovalRequired {
		return errors.New("server pool identity or manual-approval policy is invalid")
	}
	if p.IssuedAt <= 0 || p.IssuedAt > now.Unix()+300 || p.ExpiresAt <= now.Unix() || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > int64(MaxValidity/time.Second) {
		return errors.New("server pool profile expired or outside its validity window")
	}
	if len(p.Nodes) == 0 || len(p.Nodes) > MaxNodes {
		return errors.New("server pool must contain 1..16 explicitly trusted nodes")
	}
	ids, endpoints := map[string]bool{}, map[string]bool{}
	for _, node := range p.Nodes {
		if !validNodeID(node.ID) || !cleanLabel(node.Name, 80) || ids[node.ID] || endpoints[node.Address+"|"+node.DialAddress] || !validEndpoint(node.Address, false) || (node.DialAddress != "" && !validEndpoint(node.DialAddress, true)) || !validPins(node.Pins, true) || !validPins(node.InnerTLSPins, false) {
			return errors.New("server pool node, endpoint or pin set is invalid")
		}
		if node.WSPath == "" || len(node.WSPath) > 256 || node.WSPath[0] != '/' || strings.ContainsAny(node.WSPath, "?#\\\r\n\t %") || strings.Contains(node.WSPath, "//") || strings.Contains(node.WSPath, "..") {
			return errors.New("server pool websocket path is invalid")
		}
		for _, r := range node.WSPath {
			if r < 33 || r > 126 {
				return errors.New("server pool websocket path must be printable ASCII")
			}
		}
		ids[node.ID], endpoints[node.Address+"|"+node.DialAddress] = true, true
	}
	return nil
}

func (p Profile) message() ([]byte, error) {
	p.Signature = ""
	raw, err := json.Marshal(p)
	return append([]byte("otu-server-pool-v1\x00"), raw...), err
}

func (p *Profile) Sign(key ed25519.PrivateKey, now time.Time) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid pool signing key")
	}
	pub := key.Public().(ed25519.PublicKey)
	p.Version, p.ID, p.OperatorKey = ProfileVersion, OperatorID(pub), base64.StdEncoding.EncodeToString(pub)
	if err := p.Validate(now); err != nil {
		return err
	}
	msg, err := p.message()
	if err != nil {
		return err
	}
	p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))
	return nil
}

func (p Profile) Verify(now time.Time) error {
	if err := p.Validate(now); err != nil {
		return err
	}
	pub, _ := base64.StdEncoding.DecodeString(p.OperatorKey)
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	msg, merr := p.message()
	if err != nil || merr != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != p.Signature || !ed25519.Verify(pub, msg, sig) {
		return errors.New("server pool signature is invalid")
	}
	return nil
}

func Decode(raw []byte) (Profile, error) {
	var p Profile
	if len(raw) > MaxProfileSize {
		return p, errors.New("server pool profile exceeds size limit")
	}
	if err := DecodeStrict(raw, &p); err != nil {
		return p, errors.New("server pool schema is invalid; credentials and unknown fields are not accepted")
	}
	return p, nil
}

func Load(path string, now time.Time) (Profile, error) {
	raw, err := ReadDocument(path)
	if err != nil {
		return Profile{}, errors.New("server pool profile unavailable")
	}
	p, err := Decode(raw)
	if err != nil {
		return p, err
	}
	return p, p.Verify(now)
}

// ReadDocument reads a bounded regular public profile/manifest without
// changing the permissions of a user-supplied import file.
func ReadDocument(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxProfileSize {
		return nil, errors.New("pool document is linked or oversized")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("pool document changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxProfileSize+1))
	if err != nil || len(raw) > MaxProfileSize {
		return nil, errors.New("pool document unavailable or oversized")
	}
	return raw, nil
}

func (n Node) DialAddr() string {
	if n.DialAddress != "" {
		return n.DialAddress
	}
	return n.Address
}

func (n Node) ServerName() string {
	host, _, _ := net.SplitHostPort(n.Address)
	return host
}

// ContainsNode compares the entire accepted node, not just a callback's ID.
// A matching name/ID must not authorize a substituted endpoint or pin set.
func (p Profile) ContainsNode(node Node) bool {
	for _, accepted := range p.Nodes {
		if accepted.Equal(node) {
			return true
		}
	}
	return false
}

func (n Node) Equal(other Node) bool {
	if n.ID != other.ID || n.Name != other.Name || n.Address != other.Address || n.DialAddress != other.DialAddress || n.WSPath != other.WSPath || len(n.Pins) != len(other.Pins) || len(n.InnerTLSPins) != len(other.InnerTLSPins) {
		return false
	}
	for i := range n.Pins {
		if n.Pins[i] != other.Pins[i] {
			return false
		}
	}
	for i := range n.InnerTLSPins {
		if n.InnerTLSPins[i] != other.InnerTLSPins[i] {
			return false
		}
	}
	return true
}
