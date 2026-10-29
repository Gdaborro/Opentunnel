// handshakeprobe checks which handshake versions a relay admits for a
// token: tries v5 (signed with the device key when present) and v4, and
// reports each verdict. Doubles as the live v4-downgrade-gate check —
// after a peer has ever passed a signed v5 session, its v4 answer must
// be BadToken.
//
// Usage: OTU_TOKEN=<tok> go run ./tools/handshakeprobe [host:port]
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"opentunnel/internal/client"
	"opentunnel/internal/protocol"
)

func main() {
	addr := "cdn.aborro.dev:443"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	tok := os.Getenv("OTU_TOKEN")
	if tok == "" {
		base := os.Getenv("LOCALAPPDATA")
		var dev struct {
			Token string `json:"token"`
		}
		if base != "" {
			if raw, err := os.ReadFile(filepath.Join(base, "opentunnel", "device.json")); err == nil {
				_ = json.Unmarshal(raw, &dev)
				tok = dev.Token
			}
		}
	}
	if tok == "" {
		fmt.Println("no token (set OTU_TOKEN or run on a client machine)")
		os.Exit(1)
	}

	ws := func() net.Conn {
		httpc := &http.Client{Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				raw, err := net.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(raw, &tls.Config{
					ServerName: "cdn.aborro.dev",
					// Pinned in production clients; this diagnostic accepts
					// the chain — the relay is the authority being probed.
					InsecureSkipVerify: true,
				})
				if err := tc.Handshake(); err != nil {
					return nil, err
				}
				return tc, nil
			},
		}}
		// The dial ctx is scoped to the dial ONLY: reusing a context that
		// gets canceled when this helper returns kills the websocket
		// ("failed to acquire lock: context canceled"). The NetConn runs
		// on a background context; SetDeadline bounds the exchange.
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer dcancel()
		c, _, err := websocket.Dial(dctx, "wss://"+addr+"/api/v1/stream", &websocket.DialOptions{HTTPClient: httpc})
		if err != nil {
			fmt.Println("ws dial:", err)
			os.Exit(1)
		}
		conn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		return conn
	}

	statuses := map[byte]string{
		protocol.StatusOK: "OK", protocol.StatusBadToken: "BadToken",
		protocol.StatusBadVersion: "BadVersion", protocol.StatusPending: "Pending",
	}

	// v5 attempt, signed with the device key when one exists.
	salt := protocol.RandomSalt()
	if sig, ok := clientSign(salt); ok {
		conn := ws()
		if err := protocol.WriteHandshakeV5(conn, tok, salt, sig); err != nil {
			fmt.Println("v5 write:", err)
			os.Exit(1)
		}
		ver, st, err := protocol.ReadHandshakeStatus(conn)
		if err != nil {
			fmt.Println("v5 read:", err)
			os.Exit(1)
		}
		conn.Close()
		fmt.Printf("v5 (signed): ver=%d status=%d (%s)\n", ver, st, statuses[st])
	} else {
		fmt.Println("v5 (signed): skipped (no device key on this machine)")
	}

	// v4 attempt.
	conn := ws()
	if err := protocol.WriteHandshake(conn, tok); err != nil {
		fmt.Println("v4 write:", err)
		os.Exit(1)
	}
	ver, st, err := protocol.ReadHandshakeStatus(conn)
	if err != nil {
		fmt.Println("v4 read:", err)
		os.Exit(1)
	}
	fmt.Printf("v4 (no signature): ver=%d status=%d (%s)\n", ver, st, statuses[st])
	if st != protocol.StatusOK {
		conn.Close()
		return
	}
	// Complete the session the way a legacy client does (salt, AEAD
	// stream, client token) and request a target — this exposes
	// kill-switch/down states and dial verdicts without a full client.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	tsalt := protocol.RandomSalt()
	if werr := protocol.WriteSalt(conn, tsalt); werr != nil {
		fmt.Println("salt write:", werr)
		os.Exit(1)
	}
	sec, serr := protocol.ClientSideSecureStream(conn, tok, tsalt, protocol.ProfileFor("fast"))
	if serr != nil {
		fmt.Println("secure stream:", serr)
		os.Exit(1)
	}
	if werr := protocol.WriteToken(sec, tok); werr != nil {
		fmt.Println("token write:", werr)
		os.Exit(1)
	}
	if tresp, terr := protocol.ReadToken(sec); terr != nil {
		fmt.Println("token response:", terr)
		os.Exit(1)
	} else if tresp != "ok" {
		fmt.Printf("token response: %q\n", tresp)
		conn.Close()
		return
	}
	taddr, _ := protocol.ParseAddress("example.com", 80)
	if werr := taddr.Encode(sec); werr != nil {
		fmt.Println("target write:", werr)
		os.Exit(1)
	}
	hdr := make([]byte, 2)
	if _, rerr := io.ReadFull(sec, hdr); rerr != nil {
		fmt.Println("target response:", rerr)
		os.Exit(1)
	}
	switch hdr[1] {
	case protocol.StatusOK:
		fmt.Println("target request: OK (relay dialed the target)")
	case protocol.StatusBlocked:
		reason := ""
		if tokStr, rerr := protocol.ReadToken(sec); rerr == nil {
			reason = tokStr
		}
		fmt.Printf("target request: BLOCKED — %s\n", reason)
	case protocol.StatusDialFailed:
		fmt.Println("target request: dial failed (relay reachable, target unreachable)")
	default:
		fmt.Printf("target request: status=%d\n", hdr[1])
	}
	conn.Close()
}

// clientSign loads the device key and signs HandshakeMsg(token, salt),
// mirroring the client's v5 signer.
func clientSign(salt []byte) ([]byte, bool) {
	ts, err := client.NewTokenStore()
	if err != nil {
		return nil, false
	}
	df, err := ts.LoadOrCreate()
	if err != nil || df.Token == "" {
		return nil, false
	}
	raw, err := os.ReadFile(ts.SSHPrivatePath())
	if err != nil {
		return nil, false
	}
	keyAny, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, false
	}
	var ed ed25519.PrivateKey
	switch k := keyAny.(type) {
	case ed25519.PrivateKey:
		ed = k
	case *ed25519.PrivateKey:
		ed = *k
	default:
		return nil, false
	}
	return ed25519.Sign(ed, protocol.HandshakeMsg(df.Token, salt)), true
}
