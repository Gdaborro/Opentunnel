// Package config loads TOML configuration for both binaries.
package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"opentunnel/internal/authority"
	"opentunnel/internal/netutil"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/version"
)

type Server struct {
	Listen                string   `toml:"listen"`                  // e.g. ":443"
	ListenAlt             string   `toml:"listen_alt"`              // optional extra TLS port sharing cert/handler
	ListenInternal        string   `toml:"listen_internal"`         // optional PLAIN ws listener bound to loopback (for the ssh transport)
	ListenCarrierInternal string   `toml:"listen_carrier_internal"` // opt-in managed-carrier ingress; loopback only
	StaticTokenOnly       bool     `toml:"static_token_only"`       // explicit legacy/lab mode, never a DB-failure fallback
	H3                    *bool    `toml:"h3"`                      // default true; bound to the configured TCP listener's host
	InnerTLSCertFile      string   `toml:"inner_tls_cert"`
	InnerTLSKeyFile       string   `toml:"inner_tls_key"`
	RequireInnerTLS       bool     `toml:"require_inner_tls"`
	RequireChannelAuth    bool     `toml:"require_channel_auth"`
	Token                 string   `toml:"token"` // shared secret; generate with a password manager
	CertFile              string   `toml:"cert_file"`
	KeyFile               string   `toml:"key_file"`
	AcmeDomain            string   `toml:"acme_domain"`      // optional: obtain/renew a public LE cert (TLS-ALPN)
	WSPath                string   `toml:"ws_path"`          // default "/ws"
	Host                  string   `toml:"host"`             // public hostname, used for self-signed CN
	AutoApprove           bool     `toml:"auto_approve"`     // new device registrations start approved (no manual gate)
	PoolID                string   `toml:"pool_id"`          // optional trusted-pool approval authority ID
	EnrollmentLogin       bool     `toml:"enrollment_login"` // user login permits enrollment, never approval
	AuthorityID           string   `toml:"authority_id"`     // explicitly pinned central approval/accounting authority
	AuthorityURL          string   `toml:"authority_url"`    // https://host:port; relay never opens a local DB in this mode
	AuthorityNodeID       string   `toml:"authority_node_id"`
	AuthorityClientCert   string   `toml:"authority_client_cert"`
	AuthorityClientKey    string   `toml:"authority_client_key"`
	AuthorityPins         []string `toml:"authority_pins"`   // independent authority SPKI pins, not public-edge pins
	AuthorityListen       string   `toml:"authority_listen"` // panel's optional dedicated TLS 1.3 node-only API
	AuthorityCert         string   `toml:"authority_cert"`
	AuthorityKey          string   `toml:"authority_key"`
	AuthorityNodes        string   `toml:"authority_nodes"` // credential-free JSON node ID/SPKI allowlist
	// AllowRestrictedTargets disables the SSRF dial filter (loopback,
	// private, link-local/metadata, CGNAT). Default false.
	AllowRestrictedTargets bool `toml:"allow_restricted_targets"`
	AllowStreamingHTTP2    bool `toml:"allow_streaming_http2"`
	// AllowLegacyMaster accepts the shared token at the handshake while
	// clients migrate to per-device tokens. Default false.
	AllowLegacyMaster bool `toml:"allow_legacy_master"`
	// PurgeAfterDays deletes devices unseen for this many days; they must
	// re-register and be re-approved. Default 14.
	PurgeAfterDays int `toml:"purge_after_days"`
	// GeoIPDB is the path to an offline MaxMind country mmdb used by the
	// panel map. Empty = no country resolution.
	GeoIPDB string `toml:"geoip_db"`
	// PinProbeHost: when set, the relay periodically dials this host's
	// TLS endpoint (i.e. through the CDN front) to learn the certificate
	// clients actually see, and announces it in-band so pin rotation (CDN
	// edge certs, LE renewals) heals without operator action. Set it to
	// the public tunnel hostname once the domain is CDN-fronted.
	PinProbeHost string `toml:"pin_probe_host"`
	// TrustCloudflareIPs: honor CF-Connecting-IP when the TCP peer is a
	// Cloudflare edge IP, so per-IP guards, GeoIP and rate limits see the
	// real client behind the CDN. Spoofed headers from non-CF peers are
	// ignored.
	TrustCloudflareIPs bool `toml:"trust_cf_ips"`
	// RequireV5After auto-sunsets the v4 handshake migration window for
	// key-registered peers: RFC3339 or YYYY-MM-DD, e.g. "2026-12-01".
	// Empty (default) keeps per-peer enforcement only (v5_seen sticky
	// gate). Malformed values fail open — the per-peer gate still
	// protects every device that has updated.
	RequireV5After string `toml:"require_v5_after"`
	// SSHPublicHost, when set (e.g. "git.aborro.dev"), is announced in
	// every control response so clients learn the ssh tier's dial target
	// in-band — required once the tunnel domain is CDN-fronted, because
	// CDNs do not proxy port 22.
	SSHPublicHost string `toml:"ssh_public_host"`
}

// RequireV5Time parses require_v5_after; zero when unset or malformed.
func (s *Server) RequireV5Time() time.Time {
	v := strings.TrimSpace(s.RequireV5After)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

type ClientConf struct {
	Telemetry          string `toml:"telemetry"` // full (preserve) or minimal (explicit local opt-in)
	RequireChannelAuth bool   `toml:"require_channel_auth"`
	// Runtime-only, loaded from an explicitly imported signed profile. A TOML
	// file cannot silently introduce an operator or an endpoint callback.
	Pool            *serverpool.Profile    `toml:"-"`
	PoolNode        func() serverpool.Node `toml:"-"`
	PoolDialAddress string                 `toml:"-"`
	ServerAddr      string                 `toml:"server_addr"`      // host[:port]
	ServerIP        string                 `toml:"server_ip"`        // optional literal IP to dial (SNI stays server_addr host; defeats DNS sinkholing)
	ServerFallbacks []string               `toml:"server_fallbacks"` // extra entry host[:port]s, rotated when an entry fails
	Token           string                 `toml:"token"`
	Fingerprint     string                 `toml:"fingerprint"` // SHA-256 hex pin of server cert (wstls only)
	// Fingerprints are additional accepted SHA-256 pins: the leaf changes
	// at every Let's Encrypt renewal, and pins learned in-band from the
	// relay rejoin here after restarts.
	Fingerprints            []string       `toml:"fingerprints"`
	Insecure                bool           `toml:"insecure"` // dev only
	WSPath                  string         `toml:"ws_path"`
	Transport               string         `toml:"transport"`      // wstls (default) | ssh
	CarrierSOCKS            string         `toml:"carrier_socks"`  // external managed companion, loopback only
	CarrierTarget           string         `toml:"carrier_target"` // fixed remote loopback ingress
	Reality                 *RealityClient `toml:"reality"`
	InnerTLSPins            []string       `toml:"inner_tls_pins"`            // opt-in independent relay SPKI SHA-256 pins
	AllowUntrustedBootstrap bool           `toml:"allow_untrusted_bootstrap"` // recovery-only; verify enrollment independently
	AllowNonLoopbackProxy   bool           `toml:"allow_non_loopback_proxy"`  // opt-in to exposing unauthenticated listeners
	SSHUser                 string         `toml:"ssh_user"`                  // for transport="ssh"
	SSHKey                  string         `toml:"ssh_key"`                   // path to private key
	SSHPort                 string         `toml:"ssh_port"`                  // default "22"
	SSHInternal             string         `toml:"ssh_internal"`              // loopback ws target on VPS, e.g. 127.0.0.1:8081
	SSHHostKeys             string         `toml:"ssh_host_keys"`             // comma-separated SHA256:<b64> host-key pins for the ssh tier
	// SSHDialHostOverride is a direct hostname for the ssh tier to dial
	// (empty = derive from server_addr). Needed once the tunnel domain is
	// CDN-fronted — CDNs do not proxy port 22, so the ssh tier must dial a
	// plain A record. A name like git.aborro.dev reads as ordinary
	// developer traffic: bulk SSH to a git host is the most common heavy
	// SSH pattern there is.
	SSHDialHostOverride string `toml:"ssh_dial_host"`
	// SSHClientVersion is the SSH banner the ssh tier announces. Empty
	// matches the server's whitelisted OpenSSH family (transport default);
	// "-" reverts to Go's stock banner.
	SSHClientVersion string `toml:"ssh_client_version"`
	Profile          string `toml:"profile"`      // auto | fast | balanced | stealth
	FallbackSSH      *bool  `toml:"fallback_ssh"` // add ssh last-resort tier to the ladder
	Mux              *bool  `toml:"mux"`          // default true: multiplexed sessions
	UDP              *bool  `toml:"udp"`          // default true: SOCKS5 UDP ASSOCIATE
	// H3Tier adds the HTTP/3 transport between ws-tls and ssh (default
	// true): QUIC to :443 cannot be transparently intercepted, so pinned
	// handshakes reach the relay on MITM networks and bulk traffic moves
	// off SSH there. UDP-blocked networks fail through to ssh in ~8s.
	H3Tier *bool `toml:"h3_tier"`
	// ECH enables Encrypted Client Hello on ws-tls dials once the entry
	// hostname publishes an ECHConfigList (HTTPS DNS record — Cloudflare
	// publishes it automatically for eligible zones): the real SNI rides
	// encrypted behind a cover name, so SNI-based classification sees only
	// the cover. Fail-open: a rejected attempt retries without ECH over a
	// fresh socket. Default true.
	ECH *bool `toml:"ech"`
	// ECHDoH overrides the DoH resolvers (comma-separated URLs) used to
	// fetch the ECHConfigList. Empty = built-in defaults.
	ECHDoh        string   `toml:"ech_doh"`
	SOCKSAddr     string   `toml:"socks_addr"`     // default 127.0.0.1:1080
	HTTPAddr      string   `toml:"http_addr"`      // default 127.0.0.1:8118
	BypassList    []string `toml:"bypass_list"`    // extra ProxyOverride entries
	AutoUpdate    *bool    `toml:"auto_update"`    // default true: self-update from GitHub Releases
	UpdateChannel string   `toml:"update_channel"` // stable by default; canary/candidate require explicit opt-in
	HostileSSH    *bool    `toml:"hostile_ssh"`    // default true: allow the SSH last-resort tier on TLS-intercepting networks
}

// RealityClient explicitly opts into managing a separately provisioned Xray
// executable. ProfilePath contains carrier credentials and stays private.
type RealityClient struct {
	Enabled     bool   `toml:"enabled"`
	Executable  string `toml:"executable"`
	SHA256      string `toml:"sha256"`
	ProfilePath string `toml:"profile"`
	SOCKSListen string `toml:"socks_listen"`
}

// SSHHostKeyPins splits ssh_host_keys into individual pins.
func (c *ClientConf) SSHHostKeyPins() []string {
	var out []string
	for _, p := range strings.Split(c.SSHHostKeys, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// FingerprintSet merges the primary fingerprint with the rotation list.
func (c *ClientConf) FingerprintSet() []string {
	out := make([]string, 0, 1+len(c.Fingerprints))
	if fp := strings.TrimSpace(c.Fingerprint); fp != "" {
		out = append(out, fp)
	}
	for _, fp := range c.Fingerprints {
		if fp = strings.TrimSpace(fp); fp != "" {
			out = append(out, fp)
		}
	}
	return out
}

// FallbackSSHEnabled reports whether the ssh last-resort tier should be
// added to the adaptive ladder (opt-in).
func (c *ClientConf) FallbackSSHEnabled() bool { return c.FallbackSSH != nil && *c.FallbackSSH }

// SSHPortOrDefault returns the SSH port ("22" unless configured).
func (c *ClientConf) SSHPortOrDefault() string {
	if c.SSHPort == "" {
		return "22"
	}
	return c.SSHPort
}

// SSHHostOnly strips any port from ServerAddr for SSH dialing.
func (c *ClientConf) SSHHostOnly() string {
	if h, _, err := net.SplitHostPort(c.ServerAddr); err == nil {
		return h
	}
	return c.ServerAddr
}

// TransportKind returns "wstls" unless explicitly set to "ssh".
func (c *ClientConf) TransportKind() string {
	if c.Transport == "carrier" {
		return "carrier"
	}
	if c.Transport == "ssh" {
		return "ssh"
	}
	return "wstls"
}

// MuxEnabled reports the effective multiplexing setting (default true).
func (c *ClientConf) MuxEnabled() bool { return c.Mux == nil || *c.Mux }

// H3TierEnabled reports whether the HTTP/3 tier rides the ladder
// (default true: it only engages after every ws-tls profile has failed).
func (c *ClientConf) H3TierEnabled() bool { return c.H3Tier == nil || *c.H3Tier }

// ECHEnabled reports the effective ECH setting (default true).
func (c *ClientConf) ECHEnabled() bool { return c.ECH == nil || *c.ECH }

// ECHDoHURLs splits ech_doh into resolver URLs (nil = built-in defaults).
func (c *ClientConf) ECHDoHURLs() []string {
	var out []string
	for _, u := range strings.Split(c.ECHDoh, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// UDPEnabled reports the effective UDP relay setting (default true).
func (c *ClientConf) UDPEnabled() bool { return c.UDP == nil || *c.UDP }

// AutoUpdateEnabled reports the effective auto-update setting (default true).
func (c *ClientConf) AutoUpdateEnabled() bool { return c.AutoUpdate == nil || *c.AutoUpdate }

func (c *ClientConf) IdentityScope() string {
	if c.Pool != nil {
		return c.Pool.ID
	}
	return ""
}

// ControlConfig snapshots the selected node; it never mutates the shared
// runtime config as selection/failover changes concurrently with polling.
func (c *ClientConf) ControlConfig() (*ClientConf, error) {
	if c.Pool == nil {
		if c.PoolNode != nil {
			return nil, fmt.Errorf("config: pool node callback without a trusted profile")
		}
		return c, nil
	}
	if c.PoolNode == nil || c.Insecure || c.AllowUntrustedBootstrap {
		return nil, fmt.Errorf("config: trusted pool control configuration is incomplete or insecure")
	}
	if err := c.Pool.Verify(time.Now()); err != nil {
		return nil, err
	}
	node := c.PoolNode()
	if !c.Pool.ContainsNode(node) {
		return nil, fmt.Errorf("config: selected control node is not in the accepted pool profile")
	}
	copy := *c
	copy.PoolNode = nil
	copy.ServerAddr, copy.ServerIP, copy.ServerFallbacks = node.Address, "", nil
	copy.PoolDialAddress = node.DialAddr()
	copy.Fingerprint, copy.Fingerprints, copy.WSPath = node.Pins[0], append([]string(nil), node.Pins...), node.WSPath
	copy.Insecure, copy.AllowUntrustedBootstrap = false, false
	return &copy, nil
}

// entryHostPort splits server_addr into host and port (default 443).
func (c *ClientConf) entryHostPort() (string, string) {
	if h, p, err := net.SplitHostPort(c.ServerAddr); err == nil {
		return h, p
	}
	return c.ServerAddr, "443"
}

// DialHostPort is the address to open TCP toward: the IP literal when
// server_ip is set (DNS-independent), else server_addr as configured.
func (c *ClientConf) DialHostPort() string {
	if c.Pool != nil && c.PoolDialAddress != "" {
		return c.PoolDialAddress
	}
	if c.ServerIP != "" {
		_, port := c.entryHostPort()
		return net.JoinHostPort(c.ServerIP, port)
	}
	return c.ServerAddr
}

// SNIHost is the hostname presented as SNI (and pinned cert identity):
// always the server_addr host, even when dialing an IP literal.
func (c *ClientConf) SNIHost() string {
	host, _ := c.entryHostPort()
	return host
}

// SSHDialHost returns the host the ssh tier dials: the dedicated override
// first (CDN fronts do not proxy port 22), then the sinkhole-proof IP
// literal, then the server_addr host.
func (c *ClientConf) SSHDialHost() string {
	if c.SSHDialHostOverride != "" {
		return c.SSHDialHostOverride
	}
	if c.ServerIP != "" {
		return c.ServerIP
	}
	return c.SSHHostOnly()
}

// AllowHostileSSH reports whether the SSH last-resort tier may engage on
// TLS-intercepting networks (default true preserves connectivity; set false
// to forbid the conspicuous SSH fallback where stealth matters more).
func (c *ClientConf) AllowHostileSSH() bool { return c.HostileSSH == nil || *c.HostileSSH }

func LoadServer(path string) (*Server, error) {
	var s Server
	if _, err := toml.DecodeFile(path, &s); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if s.Listen == "" {
		s.Listen = ":443"
	}
	if s.PoolID != "" && (!serverpool.ValidID(s.PoolID) || s.AutoApprove || s.StaticTokenOnly || s.AllowLegacyMaster) {
		return nil, fmt.Errorf("config: a trusted pool needs a valid pool_id and manual per-device approval; legacy/automatic admission is not supported")
	}
	if s.EnrollmentLogin && s.PoolID == "" {
		return nil, fmt.Errorf("config: enrollment_login requires an explicit pool_id")
	}
	if (s.StaticTokenOnly || s.AllowLegacyMaster) && (len(s.Token) < 16 || strings.HasPrefix(s.Token, "CHANGE_ME")) {
		return nil, fmt.Errorf("config: server token is required")
	}
	for _, addr := range []string{s.ListenInternal, s.ListenCarrierInternal} {
		if addr != "" {
			if err := netutil.LoopbackEndpoint(addr); err != nil {
				return nil, fmt.Errorf("config: internal listener: %w", err)
			}
		}
	}
	if s.ListenInternal != "" && s.ListenInternal == s.ListenCarrierInternal {
		return nil, fmt.Errorf("config: internal listeners must use different ports")
	}
	if strings.TrimSpace(s.RequireV5After) != "" && s.RequireV5Time().IsZero() {
		return nil, fmt.Errorf("config: invalid require_v5_after; enforcement date was not applied")
	}
	if (s.InnerTLSCertFile == "") != (s.InnerTLSKeyFile == "") || (s.RequireInnerTLS && s.InnerTLSCertFile == "" && s.AuthorityListen == "") {
		return nil, fmt.Errorf("config: inner TLS requires both certificate and private key")
	}
	if s.RequireChannelAuth && ((!s.RequireInnerTLS && s.AuthorityListen == "") || s.StaticTokenOnly || s.AllowLegacyMaster) {
		return nil, fmt.Errorf("config: connection-bound authentication requires independent mutual TLS and per-device authority; no legacy/static fallback")
	}
	if s.AuthorityURL != "" {
		u, err := url.Parse(s.AuthorityURL)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || !authority.ValidNodeID(s.AuthorityNodeID) {
			return nil, fmt.Errorf("config: authority_url must be explicit HTTPS host:port without credentials/query/path; node ID is invalid")
		}
		if _, _, err := net.SplitHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("config: authority URL requires a TLS port")
		}
		if s.PoolID == "" || !serverpool.ValidID(s.AuthorityID) || !s.RequireChannelAuth || !s.RequireInnerTLS || s.AuthorityNodeID == "" || s.AuthorityClientCert == "" || s.AuthorityClientKey == "" || len(s.AuthorityPins) < 1 || len(s.AuthorityPins) > 2 || s.AutoApprove || s.StaticTokenOnly || s.AllowLegacyMaster || s.AuthorityListen != "" {
			return nil, fmt.Errorf("config: remote authority requires separate per-node TLS credentials, matching pool/authority IDs and channel authentication; no local/static/admin fallback")
		}
	} else if s.AuthorityNodeID != "" || s.AuthorityClientCert != "" || s.AuthorityClientKey != "" || len(s.AuthorityPins) > 0 {
		return nil, fmt.Errorf("config: authority node credentials without an explicit authority_url are not used")
	}
	for _, pin := range s.AuthorityPins {
		if !serverpool.ValidID(pin) {
			return nil, fmt.Errorf("config: invalid authority public-key pin")
		}
	}
	if s.AuthorityListen != "" {
		if s.PoolID == "" || !s.RequireChannelAuth || s.AuthorityCert == "" || s.AuthorityKey == "" || s.AuthorityNodes == "" || s.AuthorityURL != "" {
			return nil, fmt.Errorf("config: central authority listener needs a channel-authenticated pool, dedicated TLS identity and explicit node inventory")
		}
		if _, _, err := net.SplitHostPort(s.AuthorityListen); err != nil {
			return nil, fmt.Errorf("config: authority_listen needs an explicit bind endpoint")
		}
	} else if s.AuthorityCert != "" || s.AuthorityKey != "" || s.AuthorityNodes != "" {
		return nil, fmt.Errorf("config: authority server credentials without authority_listen are not used")
	}
	for _, field := range []*string{&s.InnerTLSCertFile, &s.InnerTLSKeyFile, &s.AuthorityClientCert, &s.AuthorityClientKey, &s.AuthorityCert, &s.AuthorityKey, &s.AuthorityNodes} {
		if *field != "" && !filepath.IsAbs(*field) {
			*field = filepath.Join(filepath.Dir(path), *field)
		}
	}
	return &s, nil
}

func LoadClient(path string) (*ClientConf, error) {
	var c ClientConf
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.ServerAddr == "" {
		return nil, fmt.Errorf("config: client needs server_addr")
	}
	if version.RequiresOwnServerConfiguration {
		if c.Insecure || c.AllowUntrustedBootstrap {
			return nil, fmt.Errorf("config: generic clients require verified TLS; insecure or untrusted bootstrap is not a server configuration")
		}
		pins := c.FingerprintSet()
		if len(pins) == 0 || len(pins) > 8 {
			return nil, fmt.Errorf("config: configure your own server and independently verified fingerprint before starting the generic client")
		}
		for _, pin := range pins {
			if raw, err := hex.DecodeString(pin); err != nil || len(raw) != 32 {
				return nil, fmt.Errorf("config: generic client needs valid public TLS certificate SHA256 pins from its server operator")
			}
		}
	}
	if c.Telemetry != "" && c.Telemetry != "full" && c.Telemetry != "minimal" {
		return nil, fmt.Errorf("config: telemetry must be full or minimal")
	}
	if c.UpdateChannel != "" && c.UpdateChannel != "stable" && c.UpdateChannel != "canary" && c.UpdateChannel != "candidate" {
		return nil, fmt.Errorf("config: update_channel must be stable, canary or candidate")
	}
	// token is optional: panel mode authenticates with a per-device token
	// generated on first run; token only matters for legacy/no-panel servers.
	if c.Profile == "" {
		c.Profile = "auto"
	}
	switch c.Profile {
	case "auto", "fast", "balanced", "stealth":
	default:
		return nil, fmt.Errorf("config: unknown profile %q (want auto|fast|balanced|stealth)", c.Profile)
	}
	if c.SOCKSAddr == "" && c.HTTPAddr == "" {
		c.SOCKSAddr = "127.0.0.1:1080"
	}
	for _, addr := range []string{c.SOCKSAddr, c.HTTPAddr} {
		if addr != "" && !c.AllowNonLoopbackProxy {
			if err := netutil.LoopbackEndpoint(addr); err != nil {
				return nil, fmt.Errorf("config: local proxy: %w", err)
			}
		}
	}
	if c.SOCKSAddr != "" && c.SOCKSAddr == c.HTTPAddr {
		return nil, fmt.Errorf("config: SOCKS and HTTP listeners must use different ports")
	}
	switch c.Transport {
	case "", "wstls", "ssh", "carrier":
	default:
		return nil, fmt.Errorf("config: unknown transport %q", c.Transport)
	}
	if c.CarrierSOCKS != "" {
		if err := netutil.LoopbackEndpoint(c.CarrierSOCKS); err != nil {
			return nil, fmt.Errorf("config: carrier_socks: %w", err)
		}
		if c.CarrierTarget == "" {
			c.CarrierTarget = "127.0.0.1:8082"
		}
		if err := netutil.LoopbackEndpoint(c.CarrierTarget); err != nil {
			return nil, fmt.Errorf("config: carrier_target: %w", err)
		}
		if c.CarrierSOCKS == c.SOCKSAddr || c.CarrierSOCKS == c.HTTPAddr {
			return nil, fmt.Errorf("config: external carrier must not loop through this client's own proxy")
		}
	}
	if c.Reality != nil && c.Reality.Enabled {
		if c.CarrierSOCKS != "" {
			return nil, fmt.Errorf("config: choose managed REALITY or external carrier_socks, not both")
		}
		if c.Reality.Executable == "" || c.Reality.ProfilePath == "" || len(c.Reality.SHA256) != 64 {
			return nil, fmt.Errorf("config: managed REALITY needs executable, SHA-256 and private profile")
		}
		if c.Reality.SOCKSListen == "" {
			c.Reality.SOCKSListen = "127.0.0.1:19090"
		}
		if err := netutil.LoopbackEndpoint(c.Reality.SOCKSListen); err != nil {
			return nil, fmt.Errorf("config: reality.socks_listen: %w", err)
		}
		if c.Reality.SOCKSListen == c.SOCKSAddr || c.Reality.SOCKSListen == c.HTTPAddr {
			return nil, fmt.Errorf("config: REALITY listener cannot share the client proxy port")
		}
		if digest, err := hex.DecodeString(c.Reality.SHA256); err != nil || len(digest) != 32 {
			return nil, fmt.Errorf("config: reality.sha256 must be a valid digest")
		}
		for _, field := range []*string{&c.Reality.Executable, &c.Reality.ProfilePath} {
			if !filepath.IsAbs(*field) {
				*field = filepath.Join(filepath.Dir(path), *field)
			}
		}
	}
	if c.Transport == "carrier" && c.CarrierSOCKS == "" && (c.Reality == nil || !c.Reality.Enabled) {
		return nil, fmt.Errorf("config: carrier transport requires carrier_socks")
	}
	for _, value := range c.InnerTLSPins {
		if pin, err := hex.DecodeString(value); err != nil || len(pin) != 32 {
			return nil, fmt.Errorf("config: invalid inner TLS public-key pin")
		}
	}
	if len(c.InnerTLSPins) > 8 {
		return nil, fmt.Errorf("config: inner TLS pin set too large")
	}
	if c.RequireChannelAuth && (len(c.InnerTLSPins) == 0 || c.Insecure || c.AllowUntrustedBootstrap || c.Token != "") {
		return nil, fmt.Errorf("config: connection-bound authentication needs independent relay TLS pins and a per-device identity; no insecure/shared-token bootstrap")
	}
	return &c, nil
}

func WriteServerTemplate(path string) error {
	t := `# opentunnel server configuration
listen = ":443"
# static_token_only = false # explicit legacy mode, not recommended for a device fleet
# listen_internal = "127.0.0.1:8081"
# listen_carrier_internal = "127.0.0.1:8082" # disabled unless explicitly configured
# h3 = true
# Generate a long random secret and use the SAME value in the client config:
token = "CHANGE_ME_LONG_RANDOM_SECRET"
# Leave empty to auto-generate a self-signed certificate (printed at startup).
cert_file = ""
key_file  = ""
# Public hostname clients will connect to (used for self-signed cert CN):
	host = "example.com"
	ws_path = "/api/v1/stream"
	# When true, newly registering devices start approved (no manual gate).
	# Default false: every new device waits for admin approval.
	auto_approve = false
	# Opt-in signed trusted pool (see docs/TRUSTED-SERVER-POOLS.md). The ID is
	# printed by otu-pool --gen-key; use one local or explicit central authority.
	# pool_id = "<operator-public-key SHA256>"
	# enrollment_login = true # enrollment users, separate from admin approval
	# Independent channel authentication is opt-in; canary/migrate before requiring.
	# inner_tls_cert = "relay-inner.pem"
	# inner_tls_key = "relay-inner-key.pem"
	# require_inner_tls = true
	# require_channel_auth = true
	# allow_streaming_http2 = false # explicitly validated H3-edge -> H2-origin contract
	# Remote relay ONLY: no local panel DB or administrator routes.
	# authority_url = "https://authority.example:9443"
	# authority_id = "<independently verified authority ID>"
	# authority_node_id = "node-a"
	# authority_client_cert = "node-a.pem"
	# authority_client_key = "node-a-key.pem"
	# authority_pins = ["<authority SPKI SHA256>"]
	# When true, clients may dial loopback/private/link-local/metadata
	# targets through the relay (SSRF filter off). Default false.
	allow_restricted_targets = false
	# When true, the shared token above is still accepted at the handshake
	# (migration window while clients move to per-device tokens).
	allow_legacy_master = false
	# Devices unseen for this many days are purged and must re-register /
	# be re-approved. Default 14.
	purge_after_days = 14
	# Offline MaxMind country mmdb for the panel map (empty = disabled).
	geoip_db = ""
	# Auto-sunset for the v4 handshake migration window (key-registered
	# peers only): "2026-12-01" or RFC3339. Empty = per-peer sticky gate
	# only (every device that has updated once can never be downgraded).
	require_v5_after = ""
	# Public ssh-tier dial target announced to clients in-band (control
	# channel): a plain A record the CDN does not front (CDNs do not
	# proxy port 22). Set this once the tunnel domain is CDN-fronted.
	# ssh_public_host = "git.aborro.dev"
	`
	return writeFile(path, t)
}

// WriteDefaultClientConfig writes DefaultClientTOML to path (0600).
func WriteDefaultClientConfig(path string) error {
	return writeFile(path, DefaultClientTOML)
}

func WriteClientTemplate(path string) error {
	return writeFile(path, GenericClientTOML)
}

func writeFile(path, content string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(content), 0o600)
}
