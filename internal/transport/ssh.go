// Package transport: ssh.go adds an SSH-transport. The opentunnel protocol
// runs inside a real SSH session (key-authenticated), which censorship
// middleboxes that whitelist SSH may leave untouched. The SSH endpoint is
// part of the trust boundary: the inner AEAD keys derive from a token and
// salt visible to the carrier terminator. Inner framing is not independent
// end-to-end secrecy from that endpoint; host-key verification remains vital.
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"opentunnel/internal/protocol"
)

const DefaultSSHPort = "22"

// DefaultSSHClientVersion: middleboxes whitelist by banner and the relay
// runs real OpenSSH (probe docs record a clean OpenSSH_9.6p1 heading the
// whitelist). Go's stock banner ("SSH-2.0-Go") is conspicuous next to one —
// an all-day SSH session from a tool nobody ships. Override empty.
const DefaultSSHClientVersion = "SSH-2.0-OpenSSH_9.6p1"

// Stock Ubuntu 24.04 OpenSSH client's advertised algorithms, in order. A
// Go-ordered proposal is a fingerprint of its own; the ssh tier must look
// like every other admin connecting from a Linux box. MAC list omits
// umac-* (x/crypto does not implement them) — invisible in practice
// because every listed cipher is AEAD. Keep in sync with the relay's sshd.
var (
	sshKEXAlgos = []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
		"diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
	}
	sshCipherAlgos = []string{
		"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
	}
	sshMACAlgos = []string{
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512",
	}
	sshHostKeyAlgos = []string{
		"ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519",
		"rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-512",
		"rsa-sha2-256-cert-v01@openssh.com", "rsa-sha2-256",
		"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp256",
	}
)

// SSHOptions configures the ssh transport.
type SSHOptions struct {
	Host        string // VPS address (port optional, default 22)
	User        string // SSH user, e.g. ubuntu
	KeyFile     string // path to private key (PEM RSA or OpenSSH format)
	InternalWS  string // websocket target reachable from the VPS loopback, e.g. 127.0.0.1:8081
	WSPath      string // defaults to /ws
	DialTimeout time.Duration
	// HostKeyPins pins the server host key(s) as ssh-keygen-style
	// "SHA256:<base64>" fingerprints. Empty fails CLOSED (audit round
	// three, F-2 residual): without pins any middlebox serving an SSH
	// banner can MITM the tier, relay the OTU1 handshake, harvest the
	// device token and derive the AEAD keys. InsecureHostKeys=true is
	// the explicit dev-only escape hatch.
	HostKeyPins []string
	// InsecureHostKeys accepts any host key when no pins are configured.
	// Never set outside local testing.
	InsecureHostKeys bool
	// ClientVersion is the SSH banner this client announces. Empty uses
	// DefaultSSHClientVersion (the whitelisted OpenSSH family); "-" forces
	// Go's stock banner.
	ClientVersion string
}

// SSHKeyRejectedError marks sshd refusing the client's public key
// ("unable to authenticate" / "no supported methods remain"). It is a
// configuration state — the device's key is not (or no longer)
// authorized — rather than a transient transport failure, so callers can
// back the tier off instead of re-presenting a dead key for every
// request (2026-11-05: a rotated device key made every target pay an
// authentication failure).
type SSHKeyRejectedError struct {
	Host string
	Err  error
}

func (e *SSHKeyRejectedError) Error() string {
	return fmt.Sprintf("ssh: %s refused this device's key — it may need re-approval in the panel", e.Host)
}

func (e *SSHKeyRejectedError) Unwrap() error { return e.Err }

// isSSHAuthRejection recognizes x/crypto/ssh's authentication-failure
// text (the library exposes no typed error for it).
func isSSHAuthRejection(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "unable to authenticate") ||
		strings.Contains(s, "no supported methods remain")
}

type sshTransport struct{ opt SSHOptions }

func NewSSH(opt SSHOptions) Transport { return &sshTransport{opt: opt} }

func (t *sshTransport) Name() string { return "ssh" }

func (o *SSHOptions) wsPathOrDefault() string {
	if o.WSPath == "" {
		return protocol.DefaultWSPath
	}
	return o.WSPath
}

// Dial opens an authenticated SSH session, forwards a channel to the VPS's
// loopback plain-WebSocket listener, and performs the WebSocket upgrade over
// it. The returned net.Conn is the multiplex-ready stream.
func (t *sshTransport) Dial(ctx context.Context) (net.Conn, error) {
	timeout := t.opt.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	keyRaw, err := os.ReadFile(t.opt.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("transport: read ssh key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyRaw)
	if err != nil {
		return nil, fmt.Errorf("transport: parse ssh key: %w", err)
	}

	hostPort := t.opt.Host
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		hostPort = net.JoinHostPort(hostPort, DefaultSSHPort)
	}

	clientVersion := t.opt.ClientVersion
	if clientVersion == "" {
		clientVersion = DefaultSSHClientVersion
	}
	if clientVersion == "-" {
		clientVersion = "" // let x/crypto announce its stock banner
	}
	cfg := &ssh.ClientConfig{
		User:            t.opt.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: t.hostKeyCallback(),
		Timeout:         timeout,
		ClientVersion:   clientVersion,
		// Stock-client algorithm proposals (see the lists above).
		KeyExchanges:      sshKEXAlgos,
		Ciphers:           sshCipherAlgos,
		MACs:              sshMACAlgos,
		HostKeyAlgorithms: sshHostKeyAlgos,
	}
	// ssh.Dial's Timeout only bounds the TCP connect. A peer that accepts
	// TCP and never sends an SSH banner used to hold a mux dial forever.
	// Bound the entire SSH + forwarding + WS setup with the caller context
	// and the underlying socket deadline, then transfer ownership to the conn.
	raw, err := (&net.Dialer{Timeout: timeout}).DialContext(dctx, "tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("transport: ssh dial %s: %w", hostPort, err)
	}
	owned := false
	defer func() {
		if !owned {
			_ = raw.Close()
		}
	}()
	if deadline, ok := dctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	stopSetup := context.AfterFunc(dctx, func() { _ = raw.Close() })
	defer stopSetup()
	sshConn, channels, requests, err := ssh.NewClientConn(raw, hostPort, cfg)
	if err != nil {
		if dctx.Err() != nil {
			return nil, fmt.Errorf("transport: ssh setup: %w", dctx.Err())
		}
		if isSSHAuthRejection(err) {
			return nil, &SSHKeyRejectedError{Host: hostPort, Err: err}
		}
		return nil, fmt.Errorf("transport: ssh dial %s: %w", hostPort, err)
	}
	client := ssh.NewClient(sshConn, channels, requests)

	httpTransport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			// Each HTTP connection gets its own channel. A failed upgrade
			// may close it; a legacy-path retry must never reuse that corpse.
			return openDirectTCPIP(client, t.opt.InternalWS)
		},
		ForceAttemptHTTP2: false,
	}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   timeout,
	}
	// Same legacy fallback as the outer tiers: a fresh config dials the
	// boring path, which relays predating the migration don't mount (their
	// mux answers the decoy 404 instead of 101). No subprotocol offered:
	// this rides inside SSH, and the outer tiers stopped announcing one
	// (a named subprotocol is a one-packet identification for a censor).
	dial := func(path string) (*websocket.Conn, *http.Response, error) {
		return websocket.Dial(dctx, fmt.Sprintf("ws://%s%s", t.opt.InternalWS, path), &websocket.DialOptions{
			HTTPClient: httpClient,
		})
	}
	wsConn, resp, err := dialWSWithLegacyFallback(dial, t.opt.wsPathOrDefault())
	if err != nil {
		if resp != nil {
			// Surface body for diagnosis (decoy vs protocol error).
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			httpTransport.CloseIdleConnections()
			client.Close()
			return nil, fmt.Errorf("transport: websocket over ssh: %w (status=%d body=%q)", err, resp.StatusCode, string(body))
		}
		httpTransport.CloseIdleConnections()
		client.Close()
		return nil, fmt.Errorf("transport: websocket over ssh: %w", err)
	}
	_ = resp

	if dctx.Err() != nil || !stopSetup() {
		_ = wsConn.CloseNow()
		_ = client.Close()
		return nil, fmt.Errorf("transport: ssh setup deadline reached")
	}
	_ = raw.SetDeadline(time.Time{})
	owned = true
	streamCtx, cancelStream := context.WithCancel(ctx)
	stopLifetime := context.AfterFunc(streamCtx, func() { _ = client.Close() })
	stream := websocket.NetConn(streamCtx, wsConn, websocket.MessageBinary)
	return &sshStream{
		Conn: stream,
		closer: func() {
			stopLifetime()
			cancelStream()
			_ = client.Close()
			_ = wsConn.CloseNow()
			httpTransport.CloseIdleConnections()
		},
	}, nil
}

// hostKeyCallback returns a pin-verifying callback. With no pins
// configured the tier fails CLOSED unless InsecureHostKeys is set: an
// unpinned ssh tier lets a middlebox terminate SSH, relay the OTU1
// handshake, harvest the device token and derive the session's AEAD keys
// (audit round three, F-2 residual).
func (t *sshTransport) hostKeyCallback() ssh.HostKeyCallback {
	if len(t.opt.HostKeyPins) == 0 {
		if t.opt.InsecureHostKeys {
			return ssh.InsecureIgnoreHostKey()
		}
		return func(_ string, _ net.Addr, _ ssh.PublicKey) error {
			return errors.New("transport: ssh host keys are not pinned (set ssh_host_keys, or ssh_insecure = true for local testing only)")
		}
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		sum := sha256.Sum256(key.Marshal())
		// ssh-keygen -lf prints SHA256 pins without base64 padding.
		got := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		for _, p := range t.opt.HostKeyPins {
			pin := strings.TrimRight(strings.TrimSpace(p), "=")
			if subtle.ConstantTimeCompare([]byte(pin), []byte(got)) == 1 {
				return nil
			}
		}
		return fmt.Errorf("transport: ssh host key %s does not match ssh_host_keys pins", got)
	}
}

// openDirectTCPIP asks sshd to connect to target (from the VPS side) and
// returns the channel as a net.Conn.
func openDirectTCPIP(client *ssh.Client, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	pnum, err := strconv.Atoi(portStr)
	if err != nil || pnum < 1 || pnum > 65535 || host == "" {
		return nil, errors.New("transport: invalid SSH forwarding target")
	}
	port := uint32(pnum)
	payload := ssh.Marshal(struct {
		ListenAddr string
		ListenPort uint32
		OriginAddr string
		OriginPort uint32
	}{host, port, "127.0.0.1", 0})
	ch, reqs, err := client.OpenChannel("direct-tcpip", payload)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return &sshChannelConn{Channel: ch, addr: target}, nil
}

// sshChannelConn adapts ssh.Channel to net.Conn (deadlines become no-ops;
// smux/websocket layers provide their own timeouts).
type sshChannelConn struct {
	ssh.Channel
	addr string
}

func (c *sshChannelConn) LocalAddr() net.Addr                { return dummySSHAddr{c.addr} }
func (c *sshChannelConn) RemoteAddr() net.Addr               { return dummySSHAddr{c.addr} }
func (c *sshChannelConn) SetDeadline(t time.Time) error      { return nil }
func (c *sshChannelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sshChannelConn) SetWriteDeadline(t time.Time) error { return nil }

type dummySSHAddr struct{ s string }

func (a dummySSHAddr) Network() string { return "ssh" }
func (a dummySSHAddr) String() string  { return a.s }

// sshStream couples the stream with SSH teardown.
type sshStream struct {
	net.Conn
	closer func()
	once   sync.Once
	err    error
}

func (s *sshStream) Close() error {
	s.once.Do(func() {
		s.closer() // unblock socket IO before waiting for WebSocket teardown
		s.err = s.Conn.Close()
	})
	return s.err
}
