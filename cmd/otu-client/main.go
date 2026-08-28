// otu-client is the opentunnel user-level proxy client for Windows.
// It exposes local SOCKS5 + HTTP proxies, can auto-configure the per-user
// system proxy (--auto-proxy), and always restores prior settings on exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/netenv"
	"opentunnel/internal/proxy"
	"opentunnel/internal/share"
	"opentunnel/internal/transport"
)

// version is stamped at build time via -ldflags "-X main.version=x.y.z".
var version = "dev"

func main() {
	cfgPath := flag.String("c", "client.toml", "path to client config")
	genConfig := flag.Bool("gen-config", false, "write a template config and exit")
	autoProxy := flag.Bool("auto-proxy", false, "configure the Windows user-level system proxy automatically (restored on exit)")
	restoreOnly := flag.Bool("restore", false, "restore previously saved network settings and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	shareLink := flag.Bool("share-link", false, "print an otu:// share link for this config and exit")
	qrOut := flag.String("qr", "", "with -share-link: also write a PNG QR code to this path")
	flag.Parse()

	if *showVersion {
		fmt.Println("opentunnel client", version)
		return
	}

	// Standalone mode: when -c is not given explicitly, look for client.toml
	// next to the executable (not the working directory) and create it from
	// built-in defaults on first run.
	cfgExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "c" {
			cfgExplicit = true
		}
	})
	if !cfgExplicit {
		if exe, err := os.Executable(); err == nil {
			if resolved, err := filepath.EvalSymlinks(exe); err == nil {
				exe = resolved
			}
			*cfgPath = filepath.Join(filepath.Dir(exe), *cfgPath)
		}
	}

	if *genConfig {
		if err := config.WriteClientTemplate(*cfgPath); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("template written to %s\n", *cfgPath)
		return
	}

	if _, err := os.Stat(*cfgPath); os.IsNotExist(err) {
		if werr := config.WriteDefaultClientConfig(*cfgPath); werr != nil {
			log.Fatalf("write default config: %v", werr)
		}
		fmt.Printf("[i] no config found — wrote default settings to %s\n", *cfgPath)
	}

	mgr, mgrErr := netenv.NewManager()
	if mgrErr != nil && (*autoProxy || *restoreOnly) {
		log.Fatalf("settings manager: %v", mgrErr)
	}

	// Always attempt orphan recovery: a previous session may have been
	// force-killed while system proxy was applied. In non-auto-proxy mode a
	// live-owner conflict is tolerated (that owner restores on its own exit).
	if mgr != nil {
		if err := mgr.Recover(); err != nil && *autoProxy {
			log.Fatalf("%v", err)
		}
	}

	if *restoreOnly {
		if err := mgr.Restore(); err != nil {
			log.Fatalf("restore: %v", err)
		}
		fmt.Println("network settings restored.")
		return
	}

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	// Relative ssh_key paths are resolved against the config file's
	// directory, so a key dropped next to the exe/config just works.
	if cfg.SSHKey != "" && !filepath.IsAbs(cfg.SSHKey) {
		cfg.SSHKey = filepath.Join(filepath.Dir(*cfgPath), cfg.SSHKey)
	}

	// Per-device token: the device's tunnel credential. It authenticates the
	// handshake and seeds the per-session AEAD keys; no shared secret ships
	// in the binary. The panel gates it via approval, and purges it after
	// extended inactivity (re-register → re-approve).
	tokenStore, err := client.NewTokenStore()
	if err != nil {
		log.Fatalf("token store: %v", err)
	}
	if tokenStore.IsHardBanned() {
		fmt.Println("This device is banned. Please contact the administrator.")
		if data, err := os.ReadFile(tokenStore.BanPath()); err == nil {
			fmt.Printf("Ban info: %s\n", string(data))
		}
		os.Exit(1)
	}
	device, err := tokenStore.LoadOrCreate()
	if err != nil {
		log.Fatalf("device token: %v", err)
	}
	// Register with panel (fire-and-forget; panel will create pending peer)
	go client.RegisterWithPanel(cfg, device)
	// Background heartbeat and status poll (kick/ban/pending)
	go client.PollTokenStatus(cfg, device)

	if *shareLink {
		link, lerr := share.Build(share.Params{
			ServerAddr:  cfg.ServerAddr,
			Token:       cfg.Token,
			Fingerprint: cfg.Fingerprint,
			Insecure:    cfg.Insecure,
			WSPath:      cfg.WSPath,
			Profile:     cfg.Profile,
			Mux:         boolPtr(cfg.MuxEnabled()),
			UDP:         boolPtr(cfg.UDPEnabled()),
		})
		if lerr != nil {
			log.Fatalf("share: %v", lerr)
		}
		fmt.Println(link)
		fmt.Println("\nWARNING: this link contains your secret token — share only with people you trust.")
		if *qrOut != "" {
			if werr := share.QRPNGFile(link, *qrOut, 512); werr != nil {
				log.Fatalf("qr: %v", werr)
			}
			fmt.Printf("QR code written to %s\n", *qrOut)
		} else if txt, terr := share.QRText(link); terr == nil {
			fmt.Println(txt)
		}
		return
	}

	baseOpts := transport.WSTLSOptions{
		ServerAddr:  cfg.ServerAddr,
		WSPath:      cfg.WSPath,
		Fingerprint: cfg.Fingerprint,
		Insecure:    cfg.Insecure,
	}
	dialer := client.NewAdaptive(cfg.Token, baseOpts, cfg.Profile, 15*time.Second)
	dialer.Logger = log.Default()
	// If the panel no longer knows our device token (purged after
	// inactivity), re-register and wait for approval again.
	dialer.OnAuthRejected = func() { client.RegisterWithPanel(cfg, device) }

	switch cfg.TransportKind() {
	case "ssh":
		internal := cfg.SSHInternal
		if internal == "" {
			internal = "127.0.0.1:8081"
		}
		user := cfg.SSHUser
		if user == "" {
			user = "ubuntu"
		}
		key := cfg.SSHKey
		if key == "" {
			log.Fatal("transport=ssh requires ssh_key in config")
		}
		sshAddr := net.JoinHostPort(cfg.SSHHostOnly(), cfg.SSHPortOrDefault())
		dialer.UseTransportBuilder(func(profile string) transport.Transport {
			return transport.NewSSH(transport.SSHOptions{
				Host:        sshAddr,
				User:        user,
				KeyFile:     key,
				InternalWS:  internal,
				WSPath:      cfg.WSPath,
				HostKeyPins: cfg.SSHHostKeyPins(),
			})
		})
		fmt.Println("[i] transport: ssh (tunnel inside SSH; AEAD still end-to-end)")
		if len(cfg.SSHHostKeyPins()) == 0 {
			fmt.Println("[!] WARNING: no ssh_host_keys pinned — the ssh tier will accept any host key")
		}
	default:
		fmt.Println("[i] transport: ws-tls")
		// Optional last-resort tier: if every ws-tls tier is intercepted,
		// try tunneling inside real SSH before giving up. New devices do not
		// have the key — only add the tier when the key file actually exists.
		if cfg.FallbackSSHEnabled() && cfg.SSHKey != "" {
			if _, err := os.Stat(cfg.SSHKey); err != nil {
				fmt.Printf("[i] ssh_key %q not found — skipping ssh fallback tier (ws-tls only)\n", cfg.SSHKey)
			} else {
				internal := cfg.SSHInternal
				if internal == "" {
					internal = "127.0.0.1:8081"
				}
				user := cfg.SSHUser
				if user == "" {
					user = "ubuntu"
				}
				sshAddr := net.JoinHostPort(cfg.SSHHostOnly(), cfg.SSHPortOrDefault())
				pins := cfg.SSHHostKeyPins()
				dialer.EnableSSHFallback(func() transport.Transport {
					return transport.NewSSH(transport.SSHOptions{
						Host:        sshAddr,
						User:        user,
						KeyFile:     cfg.SSHKey,
						InternalWS:  internal,
						WSPath:      cfg.WSPath,
						HostKeyPins: pins,
					})
				})
				fmt.Println("[i] ssh fallback tier enabled (last resort)")
				if len(pins) == 0 {
					fmt.Println("[!] WARNING: no ssh_host_keys pinned — the ssh tier will accept any host key")
				}
			}
		}
	}

	if cfg.MuxEnabled() {
		dialer.EnableMux()
	}
	if cfg.Profile == "auto" {
		fmt.Println("[i] adaptive mode: fast -> balanced -> stealth only as needed")
	} else {
		fmt.Printf("[i] fixed profile: %s\n", dialer.Current())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	httpAddr := cfg.HTTPAddr
	socksAddr := cfg.SOCKSAddr
	var lnHTTP, lnSOCKS net.Listener
	warnIfExposed(socksAddr, "socks_addr")
	warnIfExposed(httpAddr, "http_addr")

	if socksAddr != "" {
		lnSOCKS, err = net.Listen("tcp", socksAddr)
		if err != nil {
			log.Fatalf("socks listen: %v", err)
		}
		go proxy.ServeSOCKS5(ctx, lnSOCKS, dialer, log.Default())
		fmt.Printf("[+] SOCKS5     -> %s\n", socksAddr)
	}
	if httpAddr != "" {
		lnHTTP, err = net.Listen("tcp", httpAddr)
		if err != nil {
			log.Fatalf("http listen: %v", err)
		}
		go proxy.ServeHTTPProxy(ctx, lnHTTP, dialer, log.Default())
		fmt.Printf("[+] HTTP proxy -> %s\n", httpAddr)
	}

	if *autoProxy {
		if err := mgr.Recover(); err != nil {
			log.Fatalf("%v", err)
		}
		addr := httpAddr
		if addr == "" {
			addr = socksAddr
		}
		host, port, _ := net.SplitHostPort(addr)
		sysProxy := net.JoinHostPort(firstNonEmpty(host, "127.0.0.1"), port)
		if err := mgr.Begin(sysProxy, cfg.BypassList); err != nil {
			log.Fatalf("auto-proxy: %v", err)
		}
		defer func() { _ = mgr.Restore() }()
		// Cover window-close / logoff / shutdown, which bypass os/signal.
		netenv.InstallTerminalEventHandler(func() { _ = mgr.Restore() })
		fmt.Printf("[+] System proxy set to %s (restored on any exit)\n", sysProxy)
	}

	fmt.Println("[i] Press Ctrl+C to stop and restore settings.")

	<-ctx.Done()
	stop()
	if lnSOCKS != nil {
		_ = lnSOCKS.Close()
	}
	if lnHTTP != nil {
		_ = lnHTTP.Close()
	}
	fmt.Println("\nbye — settings restored where changed.")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// warnIfExposed flags non-loopback proxy binds: the local proxies have no
// authentication, so exposing them makes the machine an open proxy.
func warnIfExposed(addr, name string) {
	if addr == "" {
		return
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return
	}
	fmt.Printf("[!] WARNING: %s = %s is not loopback — the proxy has NO authentication; anyone who can reach it can use your tunnel\n", name, addr)
}

func boolPtr(b bool) *bool { return &b }
