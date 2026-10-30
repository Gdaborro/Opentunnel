// sshhost.go: in-band ssh-tier dial-host learning (v1.0.0, Cloudflare
// bridge). The relay announces a plain (non-CDN) A record in every control
// response; the client persists it so the ssh last-resort tier keeps a
// dialable target after the tunnel domain moves behind a CDN — CDNs do not
// proxy port 22, and requiring every device to update its config for that
// would strand exactly the devices (hostile networks) that need the ssh
// tier most.
//
// Trust: the control channel lives inside the authenticated, AEAD-sealed
// session, so only the relay can inject the value; and even a malicious
// value could only DoS the ssh tier — its host keys are pinned fail-closed,
// so a wrong host is refused, never trusted.
package client

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const sshHostFileName = "ssh_host"

func sshHostPath() (string, error) {
	ts, err := NewTokenStore()
	if err != nil {
		return "", err
	}
	return filepath.Join(ts.Dir, sshHostFileName), nil
}

// validSSHHost accepts DNS names and IPv4 literals (no scheme, port, path
// or userinfo — the port comes from ssh_port separately).
func validSSHHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return false
		}
	}
	if net.ParseIP(h) != nil {
		return true
	}
	return strings.Contains(h, ".") && !strings.HasPrefix(h, ".") && !strings.HasSuffix(h, ".")
}

var (
	learnedSSHMu   sync.Mutex
	learnedSSHHost string
	learnedSSHLoad bool
)

// LearnSSHHost records a relay-announced ssh dial host, persisting it so
// the value survives restarts (the school-network scenario: learn on any
// working network, use on the hostile one). Invalid or unchanged values
// are ignored.
func LearnSSHHost(host string) {
	host = strings.TrimSpace(host)
	if !validSSHHost(host) {
		return
	}
	learnedSSHMu.Lock()
	if learnedSSHLoad && learnedSSHHost == host {
		learnedSSHMu.Unlock()
		return
	}
	learnedSSHHost, learnedSSHLoad = host, true
	learnedSSHMu.Unlock()
	if path, err := sshHostPath(); err == nil {
		_ = os.WriteFile(path, []byte(host+"\n"), 0o600)
	}
}

// LearnedSSHHost returns the remembered ssh dial host ("" when none).
// Loads the persisted value on first call.
func LearnedSSHHost() string {
	learnedSSHMu.Lock()
	if learnedSSHLoad {
		h := learnedSSHHost
		learnedSSHMu.Unlock()
		return h
	}
	learnedSSHMu.Unlock()

	host := ""
	if path, err := sshHostPath(); err == nil {
		if b, rerr := os.ReadFile(path); rerr == nil {
			if h := strings.TrimSpace(string(b)); validSSHHost(h) {
				host = h
			}
		}
	}

	learnedSSHMu.Lock()
	learnedSSHHost, learnedSSHLoad = host, true
	learnedSSHMu.Unlock()
	return host
}
