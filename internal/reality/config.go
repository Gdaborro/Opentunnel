// Package reality manages an opt-in, separately running Xray/REALITY carrier.
// It does not implement REALITY cryptography or promise universal bypass.
package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"opentunnel/internal/netutil"
	"opentunnel/internal/privatefile"
)

const Version = "26.11.9-otu.1"
const ProfileVersion = 1

// Profile is privately provisioned. Password is the REALITY X25519 public
// value, but it is still an access parameter and must not be published/logged.
type Profile struct {
	Version    int    `json:"version"`
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"server_name"`
	UUID       string `json:"uuid"`
	Password   string `json:"password"`
	ShortID    string `json:"short_id"`
	Target     string `json:"target"`
}

type ServerParams struct {
	Listen             string
	Target             string // ONLY the opentunnel loopback ingress
	CoverTarget        string // distinct TLS fallback, selected explicitly by operator
	ServerName         string
	PrivateKey         string
	UUIDs              []string
	ShortIDs           []string
	FallbackRate       int64 // explicit tradeoff; 0 disables fallback shaping
	AllowLoopbackCover bool  // lab-only; cannot expose a public listener in this mode
}

func LoadProfile(path string) (Profile, error) {
	raw, err := privatefile.Read(path, 16<<10)
	if err != nil {
		return Profile{}, errors.New("REALITY profile unavailable")
	}
	var p Profile
	if err := decodeStrict(raw, &p); err != nil {
		return p, errors.New("invalid REALITY profile schema")
	}
	if err := p.Validate(); err != nil {
		return p, err
	}
	return p, nil
}

func (p Profile) Validate() error {
	if p.Version != ProfileVersion {
		return errors.New("unsupported REALITY profile version")
	}
	if err := endpoint(p.Endpoint, false); err != nil {
		return errors.New("invalid REALITY endpoint")
	}
	if !validServerName(p.ServerName) {
		return errors.New("REALITY cover must be an explicit DNS name")
	}
	if !validUUID(p.UUID) {
		return errors.New("REALITY user must be a canonical nonzero UUID")
	}
	if !validKey(p.Password) {
		return errors.New("invalid REALITY access parameter")
	}
	if !validShortID(p.ShortID) {
		return errors.New("REALITY short ID must contain 16 hexadecimal characters")
	}
	if err := netutil.LoopbackEndpoint(p.Target); err != nil {
		return errors.New("REALITY target must be an explicit loopback endpoint")
	}
	return nil
}

func GenerateKey() (privateKey, password string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func GenerateUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 0x40
	b[8] = (b[8] & 63) | 0x80
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func GenerateShortID() (string, error) {
	var b [8]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}
func LocalAuth() (string, string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	return "otu", base64.RawURLEncoding.EncodeToString(b[:]), nil
}

type document struct {
	Log       logConfig  `json:"log"`
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
	Routing   routing    `json:"routing"`
	Policy    policy     `json:"policy"`
}
type logConfig struct {
	Access string `json:"access"`
	Error  string `json:"error"`
	Level  string `json:"loglevel"`
}
type inbound struct {
	Tag      string          `json:"tag"`
	Listen   string          `json:"listen"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
	Stream   *stream         `json:"streamSettings,omitempty"`
}
type outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
	Stream   *stream         `json:"streamSettings,omitempty"`
}
type stream struct {
	Network  string          `json:"network"`
	Security string          `json:"security"`
	Reality  realitySettings `json:"realitySettings"`
}
type realitySettings struct {
	Show        bool           `json:"show"`
	Target      string         `json:"target,omitempty"`
	ServerNames []string       `json:"serverNames,omitempty"`
	PrivateKey  string         `json:"privateKey,omitempty"`
	ShortIDs    []string       `json:"shortIds,omitempty"`
	MaxTimeDiff int            `json:"maxTimeDiff,omitempty"`
	ServerName  string         `json:"serverName,omitempty"`
	Fingerprint string         `json:"fingerprint,omitempty"`
	Password    string         `json:"password,omitempty"`
	ShortID     string         `json:"shortId,omitempty"`
	SpiderX     string         `json:"spiderX,omitempty"`
	Upload      *fallbackLimit `json:"limitFallbackUpload,omitempty"`
	Download    *fallbackLimit `json:"limitFallbackDownload,omitempty"`
}
type fallbackLimit struct {
	AfterBytes  int64 `json:"afterBytes"`
	BytesPerSec int64 `json:"bytesPerSec"`
	BurstBytes  int64 `json:"burstBytesPerSec"`
}
type rule struct {
	Type     string   `json:"type"`
	Inbound  []string `json:"inboundTag"`
	Network  string   `json:"network,omitempty"`
	IP       []string `json:"ip,omitempty"`
	Port     string   `json:"port,omitempty"`
	Outbound string   `json:"outboundTag"`
}
type routing struct {
	Strategy string `json:"domainStrategy"`
	Rules    []rule `json:"rules"`
}
type policy struct {
	Levels map[string]level `json:"levels"`
}
type level struct {
	Handshake    int `json:"handshake"`
	ConnIdle     int `json:"connIdle"`
	UplinkOnly   int `json:"uplinkOnly"`
	DownlinkOnly int `json:"downlinkOnly"`
	BufferSize   int `json:"bufferSize"`
}
type socksSettings struct {
	Auth     string    `json:"auth"`
	Accounts []account `json:"accounts"`
	UDP      bool      `json:"udp"`
	IP       string    `json:"ip"`
}
type account struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}
type clientSettings struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
}
type serverSettings struct {
	Clients    []serverUser `json:"clients"`
	Decryption string       `json:"decryption"`
}
type serverUser struct {
	ID string `json:"id"`
}
type freedomSettings struct {
	Redirect   string      `json:"redirect"`
	FinalRules []finalRule `json:"finalRules"`
}
type finalRule struct {
	Action  string   `json:"action"`
	Network string   `json:"network,omitempty"`
	IP      []string `json:"ip,omitempty"`
	Port    string   `json:"port,omitempty"`
	Delay   string   `json:"delay,omitempty"`
}

func defaults() document {
	return document{Log: logConfig{Access: "none", Error: "none", Level: "none"}, Policy: policy{Levels: map[string]level{"0": {Handshake: 15, ConnIdle: 120, UplinkOnly: 5, DownlinkOnly: 30, BufferSize: 64}}}}
}
func raw(v any) json.RawMessage { data, _ := json.Marshal(v); return data }
func fixedRules(tag, target, dest string) []rule {
	host, port, _ := net.SplitHostPort(target)
	bits := "/32"
	if net.ParseIP(host).To4() == nil {
		bits = "/128"
	}
	return []rule{{Type: "field", Inbound: []string{tag}, Network: "tcp", IP: []string{host + bits}, Port: port, Outbound: dest}, {Type: "field", Inbound: []string{tag}, Outbound: "deny"}}
}

// ClientJSON always authenticates its loopback SOCKS ingress. The companion
// cannot be used as an open local proxy or dial a target chosen by an app.
func ClientJSON(p Profile, listen, user, password string) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := netutil.LoopbackEndpoint(listen); err != nil {
		return nil, err
	}
	if user == "" || len(user) > 64 || len(password) < 32 || len(password) > 128 {
		return nil, errors.New("invalid local companion authentication")
	}
	host, port, _ := net.SplitHostPort(listen)
	n, _ := strconv.Atoi(port)
	remote, rport, _ := net.SplitHostPort(p.Endpoint)
	rn, _ := strconv.Atoi(rport)
	d := defaults()
	d.Inbounds = []inbound{{Tag: "otu-local", Listen: host, Port: n, Protocol: "socks", Settings: raw(socksSettings{Auth: "password", Accounts: []account{{User: user, Pass: password}}, UDP: false, IP: host})}}
	d.Outbounds = []outbound{{Tag: "deny", Protocol: "blackhole", Settings: raw(struct{}{})}, {Tag: "reality", Protocol: "vless", Settings: raw(clientSettings{Address: remote, Port: rn, ID: p.UUID, Encryption: "none"}), Stream: &stream{Network: "raw", Security: "reality", Reality: realitySettings{ServerName: p.ServerName, Fingerprint: "chrome", Password: p.Password, ShortID: p.ShortID, SpiderX: "/"}}}}
	d.Routing = routing{Strategy: "AsIs", Rules: fixedRules("otu-local", p.Target, "reality")}
	return json.MarshalIndent(d, "", "  ")
}

// ServerJSON denies all but the exact requested TCP loopback destination and
// additionally rewrites freedom's final destination to that same fixed target.
// REALITY's unauthenticated TLS fallback is a separate, explicit tradeoff.
func ServerJSON(p ServerParams) ([]byte, error) {
	if err := endpoint(p.Listen, true); err != nil {
		return nil, errors.New("invalid REALITY listener")
	}
	if err := netutil.LoopbackEndpoint(p.Target); err != nil {
		return nil, err
	}
	if !validServerName(p.ServerName) || !validKey(p.PrivateKey) {
		return nil, errors.New("invalid REALITY server identity")
	}
	if len(p.UUIDs) == 0 || len(p.UUIDs) > 64 || len(p.ShortIDs) == 0 || len(p.ShortIDs) > 64 {
		return nil, errors.New("REALITY users and short IDs must be bounded and nonempty")
	}
	for _, id := range p.UUIDs {
		if !validUUID(id) {
			return nil, errors.New("invalid REALITY UUID")
		}
	}
	for _, id := range p.ShortIDs {
		if !validShortID(id) {
			return nil, errors.New("invalid REALITY short ID")
		}
	}
	if err := endpoint(p.CoverTarget, false); err != nil {
		return nil, errors.New("invalid REALITY fallback target")
	}
	cover, _, _ := net.SplitHostPort(p.CoverTarget)
	if cover != p.ServerName {
		ip, err := netip.ParseAddr(cover)
		if !p.AllowLoopbackCover || err != nil || !ip.IsLoopback() {
			return nil, errors.New("REALITY cover name must match the fallback host")
		}
		if err := netutil.LoopbackEndpoint(p.Listen); err != nil {
			return nil, errors.New("lab fallback cannot be used with a public listener")
		}
	}
	if p.FallbackRate < 0 || p.FallbackRate > 64<<20 {
		return nil, errors.New("invalid fallback rate")
	}
	host, port, _ := net.SplitHostPort(p.Listen)
	n, _ := strconv.Atoi(port)
	targetHost, targetPort, _ := net.SplitHostPort(p.Target)
	bits := "/32"
	if net.ParseIP(targetHost).To4() == nil {
		bits = "/128"
	}
	users := make([]serverUser, len(p.UUIDs))
	for i, id := range p.UUIDs {
		users[i] = serverUser{ID: id}
	}
	rs := realitySettings{Target: p.CoverTarget, ServerNames: []string{p.ServerName}, PrivateKey: p.PrivateKey, ShortIDs: p.ShortIDs, MaxTimeDiff: 120000}
	if p.FallbackRate > 0 {
		var jitter [2]byte
		if _, err := rand.Read(jitter[:]); err != nil {
			return nil, err
		}
		bps := p.FallbackRate + int64(jitter[0])*p.FallbackRate/1024
		rs.Upload = &fallbackLimit{AfterBytes: 1<<20 + int64(jitter[1])*4096, BytesPerSec: bps, BurstBytes: 2 * bps}
		rs.Download = rs.Upload
	}
	d := defaults()
	d.Inbounds = []inbound{{Tag: "otu-reality", Listen: host, Port: n, Protocol: "vless", Settings: raw(serverSettings{Clients: users, Decryption: "none"}), Stream: &stream{Network: "raw", Security: "reality", Reality: rs}}}
	d.Outbounds = []outbound{{Tag: "deny", Protocol: "blackhole", Settings: raw(struct{}{})}, {Tag: "fixed-ingress", Protocol: "freedom", Settings: raw(freedomSettings{Redirect: p.Target, FinalRules: []finalRule{{Action: "allow", Network: "tcp", IP: []string{targetHost + bits}, Port: targetPort}, {Action: "block", Delay: "0"}}})}}
	d.Routing = routing{Strategy: "AsIs", Rules: fixedRules("otu-reality", p.Target, "fixed-ingress")}
	return json.MarshalIndent(d, "", "  ")
}

// ValidateClientJSON accepts only exactly the document that the typed builder
// produces. Unknown routes, inbounds, DNS/API/logging/transport options fail
// closed. Credentials stay in memory, never in a validation diagnostic.
func ValidateClientJSON(data []byte, listen, target string) error {
	var d document
	if len(data) > 64<<10 || decodeStrict(data, &d) != nil {
		return errors.New("invalid companion configuration")
	}
	if len(d.Inbounds) != 1 || len(d.Outbounds) != 2 || d.Inbounds[0].Protocol != "socks" || d.Outbounds[1].Protocol != "vless" || d.Outbounds[1].Stream == nil {
		return errors.New("companion configuration is not a restricted client")
	}
	var local socksSettings
	var remote clientSettings
	if decodeStrict(d.Inbounds[0].Settings, &local) != nil || decodeStrict(d.Outbounds[1].Settings, &remote) != nil || len(local.Accounts) != 1 {
		return errors.New("invalid companion client settings")
	}
	rs := d.Outbounds[1].Stream.Reality
	p := Profile{Version: ProfileVersion, Endpoint: net.JoinHostPort(remote.Address, strconv.Itoa(remote.Port)), ServerName: rs.ServerName, UUID: remote.ID, Password: rs.Password, ShortID: rs.ShortID, Target: target}
	want, err := ClientJSON(p, listen, local.Accounts[0].User, local.Accounts[0].Pass)
	if err != nil {
		return err
	}
	var expected document
	if err := json.Unmarshal(want, &expected); err != nil {
		return err
	}
	canonical, _ := json.Marshal(d)
	expectedJSON, _ := json.Marshal(expected)
	if !bytes.Equal(canonical, expectedJSON) {
		return errors.New("companion config violates fixed-target policy")
	}
	return nil
}

func ValidateServerJSON(data []byte, listen, target string) error {
	var d document
	if len(data) > 64<<10 || decodeStrict(data, &d) != nil {
		return errors.New("invalid companion configuration")
	}
	if len(d.Inbounds) != 1 || len(d.Outbounds) != 2 || d.Inbounds[0].Protocol != "vless" || d.Inbounds[0].Stream == nil || d.Outbounds[1].Protocol != "freedom" {
		return errors.New("companion configuration is not a restricted server")
	}
	var users serverSettings
	var freedom freedomSettings
	if decodeStrict(d.Inbounds[0].Settings, &users) != nil || decodeStrict(d.Outbounds[1].Settings, &freedom) != nil {
		return errors.New("invalid companion server settings")
	}
	rs := d.Inbounds[0].Stream.Reality
	if len(rs.ServerNames) != 1 {
		return errors.New("companion server must use one verified cover identity")
	}
	ids := make([]string, len(users.Clients))
	for i, user := range users.Clients {
		ids[i] = user.ID
	}
	params := ServerParams{Listen: listen, Target: target, CoverTarget: rs.Target, ServerName: rs.ServerNames[0], PrivateKey: rs.PrivateKey, UUIDs: ids, ShortIDs: rs.ShortIDs}
	if netutil.LoopbackEndpoint(listen) == nil {
		params.AllowLoopbackCover = true
	}
	want, err := ServerJSON(params)
	if err != nil {
		return err
	}
	var expected document
	if err := json.Unmarshal(want, &expected); err != nil {
		return err
	}
	// Bounded optional fallback shaping is generated explicitly; every other
	// routing, security, logging and destination field must match exactly.
	for _, lim := range []*fallbackLimit{rs.Upload, rs.Download} {
		if lim != nil && (lim.BytesPerSec <= 0 || lim.BytesPerSec > 80<<20 || lim.AfterBytes < 0 || lim.AfterBytes > 16<<20 || lim.BurstBytes < lim.BytesPerSec || lim.BurstBytes > 160<<20) {
			return errors.New("invalid fallback containment")
		}
	}
	d.Inbounds[0].Stream.Reality.Upload = nil
	d.Inbounds[0].Stream.Reality.Download = nil
	canonical, _ := json.Marshal(d)
	expectedJSON, _ := json.Marshal(expected)
	if !bytes.Equal(canonical, expectedJSON) {
		return errors.New("companion server violates fixed-target confinement")
	}
	return nil
}

func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || strings.ToLower(s) != s {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return false
	}
	return !bytes.Equal(b, make([]byte, 16))
}
func validShortID(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 8 && strings.ToLower(s) == s && !bytes.Equal(b, make([]byte, 8))
}
func validKey(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && !bytes.Equal(b, make([]byte, 32))
}
func validServerName(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ToLower(s) != s || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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
func endpoint(s string, listen bool) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid port")
	}
	if host == "" && listen {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || (!listen && (ip.IsUnspecified() || ip.IsMulticast())) {
			return errors.New("invalid IP")
		}
		return nil
	}
	if !validServerName(host) {
		return fmt.Errorf("invalid host")
	}
	return nil
}
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
