// Package config loads TOML configuration for both binaries.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Server struct {
	Listen   string `toml:"listen"` // e.g. ":443"
	Token    string `toml:"token"`  // shared secret; generate with a password manager
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
	WSPath   string `toml:"ws_path"` // default "/ws"
	Host     string `toml:"host"`    // public hostname, used for self-signed CN
}

type ClientConf struct {
	ServerAddr  string   `toml:"server_addr"` // host[:port]
	Token       string   `toml:"token"`
	Fingerprint string   `toml:"fingerprint"` // SHA-256 hex pin of server cert
	Insecure    bool     `toml:"insecure"`    // dev only
	WSPath      string   `toml:"ws_path"`
	Profile     string   `toml:"profile"`     // auto | fast | balanced | stealth
	Mux         *bool    `toml:"mux"`         // default true: multiplexed sessions
	UDP         *bool    `toml:"udp"`         // default true: SOCKS5 UDP ASSOCIATE
	SOCKSAddr   string   `toml:"socks_addr"`  // default 127.0.0.1:1080
	HTTPAddr    string   `toml:"http_addr"`   // default 127.0.0.1:8118
	BypassList  []string `toml:"bypass_list"` // extra ProxyOverride entries
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
