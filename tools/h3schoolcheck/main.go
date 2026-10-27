// h3schoolcheck: one real h3 dial against production from this machine,
// through whatever network we're on. Completes the full pinned QUIC
// handshake and the OTU1 protocol auth — the same bytes the client's h3
// tier sends.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

func main() {
	// Token sources, in order: env (OTU_TOKEN), CLI arg, then this
	// machine's device.json (the usual Windows client machine case).
	token := os.Getenv("OTU_TOKEN")
	if token == "" && len(os.Args) > 1 {
		token = os.Args[1]
	}
	if token == "" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			fmt.Println("no token: set OTU_TOKEN, pass one, or run on a client machine")
			os.Exit(1)
		}
		var dev struct {
			Token string `json:"token"`
		}
		raw, err := os.ReadFile(filepath.Join(base, "opentunnel", "device.json"))
		if err != nil || json.Unmarshal(raw, &dev) != nil || dev.Token == "" {
			fmt.Println("no device token:", err)
			os.Exit(1)
		}
		token = dev.Token
	}
	t0 := time.Now()
	tr := transport.NewH3(transport.H3Options{
		ServerAddr:  "cdn.aborro.dev:443",
		ServerName:  "cdn.aborro.dev",
		Path:        "/api/v1/stream",
		Fingerprint: "e86816f5e328d6d705b5594e64e7229276a639a264ca51db7916dc3c826aeac1",
		DialTimeout: 15 * time.Second,
	})
	conn, err := tr.Dial(context.Background())
	if err != nil {
		fmt.Printf("h3 dial FAILED (in %.1fs): %v\n", time.Since(t0).Seconds(), err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("h3 dial OK in %.1fs (pinned QUIC handshake through)\n", time.Since(t0).Seconds())
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.WriteHandshake(conn, token); err != nil {
		fmt.Println("handshake write:", err)
		os.Exit(1)
	}
	if err := protocol.ReadAuthResponse(conn); err != nil {
		fmt.Printf("auth response: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("protocol auth over h3: ACCEPTED (status 0)")
}
