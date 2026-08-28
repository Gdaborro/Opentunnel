// Package transport: ssh.go adds an SSH-transport. The opentunnel protocol
// runs inside a real SSH session (key-authenticated), which censorship
// middleboxes that whitelist SSH commonly leave untouched. Confidentiality
// does not depend on trusting the SSH hop: the inner AEAD layer still
// end-to-end protects all traffic.
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

const DefaultSSHPort = "22"

// SSHOptions configures the ssh transport.
type SSHOptions struct {
	Host        string // VPS address (port optional, default 22)
	User        string // SSH user, e.g. ubuntu
	KeyFile     string // path to private key (PEM RSA or OpenSSH format)
	InternalWS  string // websocket target reachable from the VPS loopback, e.g. 127.0.0.1:8081
	WSPath      string // defaults to /ws
	DialTimeout time.Duration
	// HostKeyPins pins the server host key(s) as ssh-keygen-style
	// "SHA256:<base64>" fingerprints. Empty = accept any host key (NOT
	// recommended: an active attacker could steal the tunnel token).
	HostKeyPins []string
}

type sshTransport struct{ opt SSHOptions }

func NewSSH(opt SSHOptions) Transport { return &sshTransport{opt: opt} }

func (t *sshTransport) Name() string { return "ssh" }

func (o *SSHOptions) wsPathOrDefault() string {
	if o.WSPath == "" {
		return "/ws"
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

	cfg := &ssh.ClientConfig{
		User:            t.opt.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: t.hostKeyCallback(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", hostPort, cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: ssh dial %s: %w", hostPort, err)
	}

	ch, err := openDirectTCPIP(client, t.opt.InternalWS)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("transport: forward channel: %w", err)
	}

	url := fmt.Sprintf("ws://%s%s", t.opt.InternalWS, t.opt.wsPathOrDefault())
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return ch, nil
			},
			ForceAttemptHTTP2: false,
		},
		Timeout: timeout,
	}
	wsConn, resp, err := websocket.Dial(dctx, url, &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{"otu1"},
	})
	if err != nil {
		if resp != nil {
			// Surface body for diagnosis (decoy vs protocol error).
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			ch.Close()
			client.Close()
			return nil, fmt.Errorf("transport: websocket over ssh: %w (status=%d body=%q)", err, resp.StatusCode, string(body))
		}
		ch.Close()
		client.Close()
		return nil, fmt.Errorf("transport: websocket over ssh: %w", err)
	}
	_ = resp

	go func() {
		<-ctx.Done()
		wsConn.Close(websocket.StatusGoingAway, "")
		client.Close()
	}()

	stream := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)
	return &sshStream{
		Conn:   stream,
		closer: func() { _ = wsConn.Close(websocket.StatusNormalClosure, ""); _ = client.Close() },
	}, nil
}

// hostKeyCallback returns a pin-verifying callback, or the insecure fallback
// when no pins are configured (the client main warns loudly in that case).
func (t *sshTransport) hostKeyCallback() ssh.HostKeyCallback {
	if len(t.opt.HostKeyPins) == 0 {
		return ssh.InsecureIgnoreHostKey()
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
	var port uint32
	fmt.Sscanf(portStr, "%d", &port)
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
}

func (s *sshStream) Close() error {
	err := s.Conn.Close()
	s.closer()
	return err
}
