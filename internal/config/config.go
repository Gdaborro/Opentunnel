// Package config loads TOML configuration for both binaries.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Server struct {
	Listen         string `toml:"listen"`          // e.g. ":443"
	ListenAlt      string `toml:"listen_alt"`      // optional extra TLS port sharing cert/handler
	ListenInternal string `toml:"listen_internal"` // optional PLAIN ws listener bound to loopback (for the ssh transport)
	Token          string `toml:"token"`           // shared secret; generate with a password manager
	CertFile       string `toml:"cert_file"`
	KeyFile        string `toml:"key_file"`
	AcmeDomain     string `toml:"acme_domain"`  // optional: obtain/renew a public LE cert (TLS-ALPN)
	WSPath         string `toml:"ws_path"`      // default "/ws"
	Host           string `toml:"host"`         // public hostname, used for self-signed CN
	AutoApprove    bool   `toml:"auto_approve"` // new device registrations start approved (no manual gate)
	// AllowRestrictedTargets disables the SSRF dial filter (loopback,
	// private, link-local/metadata, CGNAT). Default false.
	AllowRestrictedTargets bool `toml:"allow_restricted_targets"`
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
	ServerAddr      string   `toml:"server_addr"`      // host[:port]
	ServerIP        string   `toml:"server_ip"`        // optional literal IP to dial (SNI stays server_addr host; defeats DNS sinkholing)
	ServerFallbacks []string `toml:"server_fallbacks"` // extra entry host[:port]s, rotated when an entry fails
	Token           string   `toml:"token"`
	Fingerprint     string   `toml:"fingerprint"` // SHA-256 hex pin of server cert (wstls only)
	// Fingerprints are additional accepted SHA-256 pins: the leaf changes
	// at every Let's Encrypt renewal, and pins learned in-band from the
	// relay rejoin here after restarts.
	Fingerprints []string `toml:"fingerprints"`
	Insecure     bool     `toml:"insecure"` // dev only
	WSPath       string   `toml:"ws_path"`
	Transport    string   `toml:"transport"`     // wstls (default) | ssh
	SSHUser      string   `toml:"ssh_user"`      // for transport="ssh"
	SSHKey       string   `toml:"ssh_key"`       // path to private key
	SSHPort      string   `toml:"ssh_port"`      // default "22"
	SSHInternal  string   `toml:"ssh_internal"`  // loopback ws target on VPS, e.g. 127.0.0.1:8081
	SSHHostKeys  string   `toml:"ssh_host_keys"` // comma-separated SHA256:<b64> host-key pins for the ssh tier
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
	ECHDoh     string   `toml:"ech_doh"`
	SOCKSAddr  string   `toml:"socks_addr"`  // default 127.0.0.1:1080
	HTTPAddr   string   `toml:"http_addr"`   // default 127.0.0.1:8118
	BypassList []string `toml:"bypass_list"` // extra ProxyOverride entries
	AutoUpdate *bool    `toml:"auto_update"` // default true: self-update from GitHub Releases
	HostileSSH *bool    `toml:"hostile_ssh"` // default true: allow the SSH last-resort tier on TLS-intercepting networks
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
	if s.Token == "" {
		return nil, fmt.Errorf("config: server token is required")
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
	return &c, nil
}

func WriteServerTemplate(path string) error {
	t := `# opentunnel server configuration
listen = ":443"
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

// DefaultClientTOML is the built-in configuration written on first run when
// no config file exists, so the client works as a standalone executable.
const DefaultClientTOML = `# opentunnel client — default configuration (auto-generated on first run)
server_addr = "cdn.aborro.dev:443"
# server_ip: literal IP dialed instead of resolving server_addr (SNI and
# cert pin stay on the hostname above). Set this to survive DNS sinkholing.
# server_ip = ""
# server_fallbacks: extra entry host[:port]s, rotated when an entry fails
# or looks shaped. Needs a second IP/hostname to matter.
# server_fallbacks = []
fingerprint = "e86816f5e328d6d705b5594e64e7229276a639a264ca51db7916dc3c826aeac1"
# fingerprints: extra accepted pins for certificate rotation. The relay
# announces its current pin in-band and clients learn it automatically;
# this list is for pre-staging or manual pin updates.
# fingerprints = []
insecure = false
ws_path = "/api/v1/stream"
profile = "auto"
mux = true
udp = true
# HTTP/3 tier (default on): QUIC to :443 cannot be transparently
# intercepted, so pinned handshakes get through on MITM networks — bulk
# traffic rides "ordinary h3 browsing" instead of SSH there. Only
# engages after every ws-tls profile has failed; UDP-blocked networks
# fall through to ssh in seconds.
h3_tier = true
# ECH (Encrypted Client Hello, default on): once the server host
# publishes an ECHConfigList (HTTPS DNS record — Cloudflare publishes it
# automatically), the real SNI rides encrypted behind a cover name.
# Fail-open: a rejected attempt retries without ECH.
ech = true
# Last-resort tier for networks that intercept TLS: tunnel inside real SSH.
# Drop tun.key next to this config to enable it (skipped when missing).
fallback_ssh = true
# On intercepting networks SSH is conspicuous: set false to forbid the
# SSH tier there (stealth TLS tiers only; may leave you offline).
hostile_ssh = true
ssh_port = "22"
ssh_user = "tun"
ssh_key = "tun.key"
ssh_internal = "127.0.0.1:8081"
ssh_host_keys = "SHA256:msXZMQ8kGmiZF6bt75T3aWtL2ebPnWtZ6+X1vs69Jas,SHA256:og9K+1+YtASuye2jO06RN3V6TA/eK+/zIMF8GHcsLyQ,SHA256:tWpmC5YfGj9UJD9iDb/FlkeCO/m/2pB59vGRSKvTl5o"
# Direct hostname the ssh tier dials (empty = derive from server_addr).
# Once the tunnel domain is CDN-fronted (CDNs don't proxy port 22), point
# this at a plain A record like git.aborro.dev — bulk SSH to a git host is
# the most ordinary heavy-SSH pattern there is.
# ssh_dial_host = "git.aborro.dev"
# SSH banner the ssh tier announces (default matches the server's OpenSSH
# family per the firewall probe; "-" reverts to Go's stock banner).
# ssh_client_version = "SSH-2.0-OpenSSH_9.6p1"
socks_addr = "127.0.0.1:1080"
http_addr = "127.0.0.1:18080"
# Bypass list stays neutral — operator domains no longer ride the visible
# WinINET ProxyOverride (loop protection is built into the client itself:
# targets matching a configured entry dial direct instead of tunneling).
bypass_list = []
`

// WriteDefaultClientConfig writes DefaultClientTOML to path (0600).
func WriteDefaultClientConfig(path string) error {
	return writeFile(path, DefaultClientTOML)
}

func WriteClientTemplate(path string) error {
	t := `# opentunnel client configuration
server_addr = "example.com:443"
token = "CHANGE_ME_LONG_RANDOM_SECRET"
# Paste the fingerprint printed by the server at startup (SHA-256 hex):
fingerprint = ""
insecure = false        # NEVER true outside local testing
ws_path = "/api/v1/stream"
# auto = start fast, escalate to balanced/stealth only when blocked,
# then drop back to fast automatically (recommended):
profile = "auto"
# Multiplexing (recommended): one tunnel session, many connections.
mux = true
udp = true              # SOCKS5 UDP ASSOCIATE over the tunnel
# Last-resort tier: if all TLS tiers get intercepted, tunnel inside real SSH.
# Requires ssh_user + ssh_key (+ server running listen_internal).
fallback_ssh = false
# Allow that SSH tier on intercepting networks (conspicuous but connected).
hostile_ssh = true
ssh_user = "ubuntu"
ssh_key = 'C:\path\to\ssh-key'
ssh_internal = "127.0.0.1:8081"
# SSH banner announced by the ssh tier (default = whitelisted OpenSSH family;
# "-" reverts to Go's stock banner).
# ssh_client_version = "SSH-2.0-OpenSSH_9.6p1"
# ECH (Encrypted Client Hello): hides the real server name behind the
# ECHConfig's cover name once the host publishes one (HTTPS DNS record —
# Cloudflare publishes it automatically). Fail-open. Default: on.
ech = true
# ech_doh = "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query"
socks_addr = "127.0.0.1:1080"
http_addr = "127.0.0.1:8118"
bypass_list = ["*.internal.example.com"]
`
	return writeFile(path, t)
}

func writeFile(path, content string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(content), 0o600)
}
