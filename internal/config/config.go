// Package config loads TOML configuration for both binaries.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Server struct {
	Listen         string `toml:"listen"`          // e.g. ":443"
	ListenAlt      string `toml:"listen_alt"`      // optional extra TLS port sharing cert/handler
	ListenInternal string `toml:"listen_internal"` // optional PLAIN ws listener bound to loopback (for the ssh transport)
	Token          string `toml:"token"`           // shared secret; generate with a password manager
	CertFile       string `toml:"cert_file"`
	KeyFile        string `toml:"key_file"`
	AcmeDomain     string `toml:"acme_domain"` // optional: obtain/renew a public LE cert (TLS-ALPN)
	WSPath         string `toml:"ws_path"`     // default "/ws"
	Host           string `toml:"host"`        // public hostname, used for self-signed CN
}

type ClientConf struct {
	ServerAddr  string   `toml:"server_addr"` // host[:port]
	Token       string   `toml:"token"`
	Fingerprint string   `toml:"fingerprint"` // SHA-256 hex pin of server cert (wstls only)
	Insecure    bool     `toml:"insecure"`    // dev only
	WSPath      string   `toml:"ws_path"`
	Transport   string   `toml:"transport"`    // wstls (default) | ssh
	SSHUser     string   `toml:"ssh_user"`     // for transport="ssh"
	SSHKey      string   `toml:"ssh_key"`      // path to private key
	SSHPort     string   `toml:"ssh_port"`     // default "22"
	SSHInternal string   `toml:"ssh_internal"` // loopback ws target on VPS, e.g. 127.0.0.1:8081
	Profile     string   `toml:"profile"`      // auto | fast | balanced | stealth
	FallbackSSH *bool    `toml:"fallback_ssh"` // add ssh last-resort tier to the ladder
	Mux         *bool    `toml:"mux"`          // default true: multiplexed sessions
	UDP         *bool    `toml:"udp"`          // default true: SOCKS5 UDP ASSOCIATE
	SOCKSAddr   string   `toml:"socks_addr"`   // default 127.0.0.1:1080
	HTTPAddr    string   `toml:"http_addr"`    // default 127.0.0.1:8118
	BypassList  []string `toml:"bypass_list"`  // extra ProxyOverride entries
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

// UDPEnabled reports the effective UDP relay setting (default true).
func (c *ClientConf) UDPEnabled() bool { return c.UDP == nil || *c.UDP }

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
	if c.ServerAddr == "" || c.Token == "" {
		return nil, fmt.Errorf("config: client needs server_addr and token")
	}
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
ws_path = "/ws"
`
	return writeFile(path, t)
}

// DefaultClientTOML is the built-in configuration written on first run when
// no config file exists, so the client works as a standalone executable.
const DefaultClientTOML = `# opentunnel client — default configuration (auto-generated on first run)
server_addr = "cdn.aborro.dev:443"
token = "497bb6b977cfb87c439a088687d0b640edd741d828c50aa6fecfba7f5854400f"
fingerprint = "e86816f5e328d6d705b5594e64e7229276a639a264ca51db7916dc3c826aeac1"
insecure = false
ws_path = "/ws"
profile = "auto"
mux = true
udp = true
# Last-resort tier for networks that intercept TLS: tunnel inside real SSH.
# Drop tun.key next to this config to enable it (skipped when missing).
fallback_ssh = true
ssh_port = "22"
ssh_user = "tun"
ssh_key = "tun.key"
ssh_internal = "127.0.0.1:8081"
socks_addr = "127.0.0.1:1080"
http_addr = "127.0.0.1:18080"
bypass_list = ["cdn.aborro.dev", "vpn.aborro.dev", "*.aborro.dev", "localhost", "127.0.0.1"]
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
ws_path = "/ws"
# auto = start fast, escalate to balanced/stealth only when blocked,
# then drop back to fast automatically (recommended):
profile = "auto"
# Multiplexing (recommended): one tunnel session, many connections.
mux = true
udp = true              # SOCKS5 UDP ASSOCIATE over the tunnel
# Last-resort tier: if all TLS tiers get intercepted, tunnel inside real SSH.
# Requires ssh_user + ssh_key (+ server running listen_internal).
fallback_ssh = false
ssh_user = "ubuntu"
ssh_key = 'C:\path\to\ssh-key'
ssh_internal = "127.0.0.1:8081"
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
