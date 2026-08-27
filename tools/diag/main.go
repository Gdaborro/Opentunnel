package main

import (
	"context"
	"fmt"
	"os"

	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

func main() {
	cfg, err := config.LoadClient(os.Args[1])
	if err != nil { fmt.Println("load:", err); return }
	base := transport.WSTLSOptions{ServerAddr: cfg.ServerAddr, WSPath: cfg.WSPath, Fingerprint: cfg.Fingerprint, Insecure: cfg.Insecure}
	ad := client.NewAdaptive(cfg.Token, base, cfg.Profile, 15e9)
	if cfg.MuxEnabled() { ad.EnableMux() }
	if cfg.FallbackSSHEnabled() && cfg.SSHKey != "" {
		ad.EnableSSHFallback(func() transport.Transport {
			return transport.NewSSH(transport.SSHOptions{Host: cfg.SSHHostOnly()+":"+cfg.SSHPortOrDefault(), User: cfg.SSHUser, KeyFile: cfg.SSHKey, InternalWS: "127.0.0.1:8081", WSPath: cfg.WSPath})
		})
	}
	target, _ := protocol.ParseAddress("example.com", 443)
	fmt.Println("dialing", target, "current tier", ad.Current())
	conn, err := ad.DialTunnel(context.Background(), target)
	if err != nil { fmt.Printf("dial err: %v\n", err); return }
	defer conn.Close()
	fmt.Println("tunnel ok tier", ad.Current(), "local", conn.LocalAddr(), "remote", conn.RemoteAddr())
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	fmt.Printf("read %d %q\n", n, string(buf[:n]))
}
