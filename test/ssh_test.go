package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"opentunnel/internal/client"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// All keys and credentials in this fixture are synthetic. No production
// endpoint, operator credential, or real network inventory is used.
func testSSHForwarder(t *testing.T, destination string) (transport.SSHOptions, *atomic.Int32) {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, _ := ssh.NewSignerFromKey(hostPrivate)
	clientSigner, _ := ssh.NewSignerFromKey(clientPrivate)
	keyBlock, err := ssh.MarshalPrivateKey(clientPrivate, "synthetic fixture")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "fixture-ssh-key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() == "fixture" && bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, fmt.Errorf("fixture key rejected")
	}}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = true
			mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				defer func() { mu.Lock(); delete(conns, c); mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				sc, channels, requests, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				accepted.Add(1)
				defer sc.Close()
				_ = c.SetDeadline(time.Time{})
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "direct-tcpip" {
						_ = incoming.Reject(ssh.Prohibited, "forwarding only")
						continue
					}
					var info struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if ssh.Unmarshal(incoming.ExtraData(), &info) != nil || net.JoinHostPort(info.Host, strconv.Itoa(int(info.Port))) != destination {
						_ = incoming.Reject(ssh.Prohibited, "fixture destination only")
						continue
					}
					up, err := net.DialTimeout("tcp", destination, time.Second)
					if err != nil {
						_ = incoming.Reject(ssh.ConnectionFailed, "fixture unavailable")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						up.Close()
						continue
					}
					go ssh.DiscardRequests(requests)
					go func(ch ssh.Channel, up net.Conn) {
						defer ch.Close()
						defer up.Close()
						go func() { _, _ = io.Copy(ch, up); _ = ch.CloseWrite() }()
						_, _ = io.Copy(up, ch)
					}(channel, up)
				}
			}(conn)
		}
	}()
	return transport.SSHOptions{Host: ln.Addr().String(), User: "fixture", KeyFile: keyPath,
		InternalWS: destination, HostKeyPins: []string{ssh.FingerprintSHA256(hostSigner.PublicKey())}, DialTimeout: 5 * time.Second}, &accepted
}

func TestBulkSSHTransfersAndWarmSessionSurviveRequestCancellation(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	// A legacy-only listener also tests that a failed first upgrade gets a
	// fresh forwarding channel rather than reusing a closed SSH channel.
	relay := httptest.NewServer(server.WithIngress(server.Handler(server.Options{
		Token: token, WSPath: protocol.LegacyWSPath, AllowRestrictedTargets: true,
	}), server.IngressSSH))
	defer relay.Close()
	options, accepted := testSSHForwarder(t, relay.Listener.Addr().String())
	cl := client.NewWithOptions(transport.NewSSH(options), client.Options{Token: token, Mux: true, MuxSessions: 2, DialTimeout: 5 * time.Second})
	defer cl.Close()
	block := make([]byte, 64<<10)
	for i := range block {
		block[i] = byte(i % 251)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		w.Header().Set("Content-Length", strconv.Itoa(size))
		for remaining := size; remaining > 0; {
			n := min(remaining, len(block))
			if _, err := w.Write(block[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}))
	defer target.Close()
	host, port, _ := net.SplitHostPort(target.Listener.Addr().String())
	addr, _ := parseAddrForTest(host, port)
	for _, size := range []int{2 << 20, 20 << 20, 2 << 20} {
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := cl.DialTunnel(ctx, addr)
		cancel() // must not cancel the pool's warm session
		if err != nil {
			t.Fatalf("SSH bulk setup: %v", err)
		}
		_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
		_, err = fmt.Fprintf(stream, "GET /?size=%d HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n", size)
		if err != nil {
			stream.Close()
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(stream), nil)
		if err != nil {
			stream.Close()
			t.Fatal(err)
		}
		gotHash := sha256.New()
		n, err := io.Copy(gotHash, resp.Body)
		resp.Body.Close()
		stream.Close()
		wantHash := sha256.New()
		for left := size; left > 0; {
			count := min(left, len(block))
			_, _ = wantHash.Write(block[:count])
			left -= count
		}
		if err != nil || n != int64(size) || !bytes.Equal(gotHash.Sum(nil), wantHash.Sum(nil)) {
			t.Fatalf("SSH transfer %d bytes stalled or corrupted: n=%d err=%v", size, n, err)
		}
	}
	if accepted.Load() != 1 {
		t.Fatalf("warm SSH session was not reused: %d authentications", accepted.Load())
	}
}
