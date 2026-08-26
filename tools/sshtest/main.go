package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

func main() {
	host := os.Args[1] // e.g. 158.178.137.23:22
	user := os.Args[2]
	keyFile := os.Args[3]
	target := os.Args[4] // e.g. 127.0.0.1:8081

	keyRaw, _ := os.ReadFile(keyFile)
	signer, _ := ssh.ParsePrivateKey(keyRaw)
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err := ssh.Dial("tcp", host, cfg)
	if err != nil { fmt.Println("ssh dial:", err); return }
	defer client.Close()
	fmt.Println("ssh connected")

	// Test 1: raw HTTP over channel
	fmt.Println("--- raw HTTP GET /ws ---")
	rawHTTPTest(client, target)

	// Test 2: websocket dial over channel
	fmt.Println("--- websocket dial ---")
	wsTest(client, target)
}

func rawHTTPTest(client *ssh.Client, target string) {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint32
	fmt.Sscanf(portStr, "%d", &port)
	payload := ssh.Marshal(struct{ ListenAddr string; ListenPort uint32; OriginAddr string; OriginPort uint32 }{host, port, "127.0.0.1", 0})
	ch, reqs, err := client.OpenChannel("direct-tcpip", payload)
	if err != nil { fmt.Println("open:", err); return }
	go ssh.DiscardRequests(reqs)
	defer ch.Close()
	fmt.Fprintf(ch, "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:8081\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: otu1\r\n\r\n")
	buf := make([]byte, 4096)
	n, _ := ch.Read(buf)
	fmt.Printf("response: %q\n", string(buf[:n]))
}

func wsTest(client *ssh.Client, target string) {
	host, portStr, _ := net.SplitHostPort(target)
	var port uint32
	fmt.Sscanf(portStr, "%d", &port)
	payload := ssh.Marshal(struct{ ListenAddr string; ListenPort uint32; OriginAddr string; OriginPort uint32 }{host, port, "127.0.0.1", 0})
	ch, reqs, err := client.OpenChannel("direct-tcpip", payload)
	if err != nil { fmt.Println("open ws:", err); return }
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	// mimic sshTransport's http client
	url := fmt.Sprintf("ws://%s/ws", target)
		hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return &chanConn{Channel: ch}, nil },
			ForceAttemptHTTP2: false,
		},
	}
	// use background context to avoid timeout
	ws, resp, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPClient: hc, Subprotocols: []string{"otu1"}})
	if err != nil {
		fmt.Printf("ws dial err: %v\n", err)
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("resp status %d body %q hdr %v\n", resp.StatusCode, string(body), resp.Header)
		}
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	fmt.Println("ws dial OK")
}

type chanConn struct{ ssh.Channel }
func (c *chanConn) LocalAddr() net.Addr { return dummyAddr{} }
func (c *chanConn) RemoteAddr() net.Addr { return dummyAddr{} }
func (c *chanConn) SetDeadline(t time.Time) error { return nil }
func (c *chanConn) SetReadDeadline(t time.Time) error { return nil }
func (c *chanConn) SetWriteDeadline(t time.Time) error { return nil }
type dummyAddr struct{}
func (dummyAddr) Network() string { return "ssh" }
func (dummyAddr) String() string { return "ssh" }
