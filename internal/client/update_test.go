package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)
func TestIsNewer(t *testing.T) {
	cases := []struct {
		current, remote string
		want            bool
	}{
		{"0.9.0", "v0.9.1", true},
		{"0.9.0", "v0.10.0", true},
		{"0.9.0", "v1.0.0", true},
		{"0.9.1", "v0.9.1", false},
		{"0.9.2", "v0.9.1", false},
		{"1.0.0", "v0.9.9", false},
		{"0.9.0", "garbage", false},
		{"dev", "v0.9.1", false},
		{"v0.9.0", "0.9.1", true},
	}
	for _, c := range cases {
		if got := isNewer(c.current, c.remote); got != c.want {
			t.Errorf("isNewer(%q,%q)=%v want %v", c.current, c.remote, got, c.want)
		}
	}
}

func TestExpectedSHA256(t *testing.T) {
	body := "## v0.9.1\n\nFixes.\n\nSHA256: abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
	want := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if got := expectedSHA256(body); got != want {
		t.Fatalf("got %q", got)
	}
	if got := expectedSHA256("no hash here"); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
	if got := expectedSHA256("sha256: tooshort"); got != "" {
		t.Fatalf("short hash must be rejected, got %q", got)
	}
}

// stubSocks5 is a minimal SOCKS5 CONNECT server for tests: it accepts one
// no-auth client, reads a CONNECT request, dials the target itself, replies
// success, then pipes bytes both ways.
func stubSocks5(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 262)
				// greeting: VER NMETHODS METHODS
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				nm := int(buf[1])
				if _, err := io.ReadFull(c, buf[:nm]); err != nil {
					return
				}
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
					return
				}
				// request: VER CMD RSV ATYP ...
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				if buf[1] != 0x01 {
					return
				}
				var host string
				var port int
				switch buf[3] {
				case 0x01: // IPv4
					if _, err := io.ReadFull(c, buf[:6]); err != nil {
						return
					}
					host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
					port = int(buf[4])<<8 | int(buf[5])
				case 0x03: // domain
					if _, err := io.ReadFull(c, buf[:1]); err != nil {
						return
					}
					n := int(buf[0])
					if _, err := io.ReadFull(c, buf[:n+2]); err != nil {
						return
					}
					host = string(buf[:n])
					port = int(buf[n])<<8 | int(buf[n+1])
				case 0x04: // IPv6
					if _, err := io.ReadFull(c, buf[:18]); err != nil {
						return
					}
					var ip net.IP = append(net.IP{}, buf[:16]...)
					host = ip.String()
					port = int(buf[16])<<8 | int(buf[17])
				default:
					return
				}
				up, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
				if err != nil {
					c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// TestSocksDialContextViaStub proves the SOCKS fallback path end to end:
// a raw TCP connection opened through the stub proxy must reach the target
// server. (The direct-first orchestration around it is covered by the live
// school-network check; here we pin the SOCKS leg itself.)
func TestSocksDialContextViaStub(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(c)
		}
	}()

	socksAddr, stopSocks := stubSocks5(t)
	defer stopSocks()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := socksDialContext(ctx, socksAddr, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("SOCKS dial failed: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "ping"); err != nil {
		t.Fatalf("write through SOCKS failed: %v", err)
	}
}

// TestUpdateClientDirectStillWorks guards the fast path: with no SOCKS
// configured, updateClient must behave like a normal client.
func TestUpdateClientDirectStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct-ok")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := updateClient("").Do(req)
	if err != nil {
		t.Fatalf("direct request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "direct-ok" {
		t.Fatalf("unexpected body %q", body)
	}
}
