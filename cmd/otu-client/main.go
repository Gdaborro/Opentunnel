// otu-client is the opentunnel user-level proxy client for Windows.
// It exposes local SOCKS5 + HTTP proxies, can auto-configure the per-user
// system proxy (--auto-proxy), and always restores prior settings on exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"opentunnel/internal/client"
	"opentunnel/internal/config"
	"opentunnel/internal/netenv"
	"opentunnel/internal/proxy"
	"opentunnel/internal/share"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

// crashLogPath is where panics and fatal errors are mirrored. The console
// hides itself in double-click mode, so the file is the only reliable trace
// after an unexpected exit.
func crashLogPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "opentunnel", "crash.log")
}

// setupCrashLog mirrors log output to crash.log (best effort; never fatal).
func setupCrashLog() {
	if err := os.MkdirAll(filepath.Dir(crashLogPath()), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(crashLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.SetPrefix("otu ")
}

// safeGo runs fn in a goroutine that cannot take the process down: a panic
// is logged (console + crash.log) and swallowed. The tunnel, proxy ports
// and system settings survive a fault in any one background worker.
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("worker %s panicked: %v", name, r)
			}
		}()
		fn()
	}()
}

// singleInstance detects an already-running otu-client (live lock journal or
// our ports held by an otu process) and returns true. Callers print a short
// friendly note and exit quietly instead of looking like a crash.
func singleInstance(mgr *netenv.Manager, socksAddr, httpAddr string) bool {
	if mgr != nil {
		if err := mgr.Recover(); err != nil {
			// Journal + live lock holder = another instance is running.
			fmt.Println("otu is already running in the background.")
			fmt.Println("Nothing to do - this window closes. Use stop-otu.bat to stop it.")
			time.Sleep(3 * time.Second)
			return true
		}
	}
	// Ports held by an otu process (no journal, e.g. manual mode) — same story.
	for _, addr := range []string{socksAddr, httpAddr} {
		if addr == "" {
			continue
		}
		if l, err := net.Listen("tcp", addr); err != nil {
			// Someone holds the port; check it is actually otu (PID reuse /
			// unrelated app would otherwise fake a conflict).
			if netenv.PortHeldByOtu(addr) {
				fmt.Println("otu is already running in the background.")
				fmt.Println("Nothing to do - this window closes. Use stop-otu.bat to stop it.")
				time.Sleep(3 * time.Second)
				return true
			}
		} else {
			_ = l.Close()
		}
	}
	return false
}

// portFailExit reports a proxy-port bind failure in plain language, restores
// any journaled settings so this path can never leave the proxy stuck, and
// exits without looking like a crash.
func portFailExit(addr string, err error, mgr *netenv.Manager) {
	fmt.Printf("\n[X] Could not start the proxy on %s (%v).\n", addr, err)
	fmt.Println("    Another otu may already be running, or another app uses this port.")
	if mgr != nil {
		if rerr := mgr.Restore(); rerr == nil {
			fmt.Println("    Network settings were restored to normal.")
		}
	}
	fmt.Println("\nPress Enter to close...")
	fmt.Scanln()
	os.Exit(1)
}

// doubleClickMode reports whether the current run was launched with no
// arguments (Explorer double-click).
var doubleClick bool

// main is the panic shield: whatever happens inside run(), settings are
// restored before the process exits, and the panic is recorded in crash.log
// (the console may be hidden, so the file is the only trace).
func main() {
	setupCrashLog()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC (main): %v", r)
			fmt.Println("[!] Something went wrong. Your network settings are being restored.")
			if mgr, err := netenv.NewManager(); err == nil {
				_ = mgr.Restore()
			}
			if doubleClick {
				time.Sleep(5 * time.Second)
			}
		}
	}()
	run()
}

func run() {
	cfgPath := flag.String("c", "client.toml", "path to client config")
	genConfig := flag.Bool("gen-config", false, "write a template config and exit")
	autoProxy := flag.Bool("auto-proxy", false, "configure the Windows user-level system proxy automatically (restored on exit)")
	restoreOnly := flag.Bool("restore", false, "restore previously saved network settings and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	shareLink := flag.Bool("share-link", false, "print an otu:// share link for this config and exit")
	qrOut := flag.String("qr", "", "with -share-link: also write a PNG QR code to this path")
	flag.Parse()

	// Double-click mode: launched with no arguments from Explorer. Route the
	// browser automatically and keep the window informative; everything is
	// still restored on exit, crash, or window close.
	doubleClick = flag.NFlag() == 0 && flag.NArg() == 0
	if doubleClick {
		*autoProxy = true
	}

	if *showVersion {
		fmt.Println("opentunnel client", version.Version)
		return
	}

	// Everything from here on is mirrored to crash.log: the console hides
	// itself in double-click mode, so unexpected exits must leave a trace.
	setupCrashLog()

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
		// Also drop a stop helper next to the exe: the double-click console
		// hides itself, so recipients need an obvious off switch. It kills
		// the client then runs its own --restore to put network settings
		// back immediately (no admin needed).
		if exe, eerr := os.Executable(); eerr == nil {
			stop := filepath.Join(filepath.Dir(exe), "stop-otu.bat")
			if _, serr := os.Stat(stop); os.IsNotExist(serr) {
				bat := "@echo off\r\n" +
					"taskkill /IM otu-client.exe /F >nul 2>&1\r\n" +
					"\"%~dp0otu-client.exe\" --restore >nul 2>&1\r\n" +
					"echo otu stopped - your normal connection is restored.\r\n" +
					"pause\r\n"
				_ = os.WriteFile(stop, []byte(bat), 0o755)
			}
		}
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

	// Friendly single-instance: if another otu is already running, say so
	// and exit quietly — never look like a crash loop.
	if singleInstance(mgr, cfg.SOCKSAddr, cfg.HTTPAddr) {
		return
	}	// Relative ssh_key paths are resolved against the config file's
	// directory, so a key dropped next to the exe/config just works.
	if cfg.SSHKey != "" && !filepath.IsAbs(cfg.SSHKey) {
		cfg.SSHKey = filepath.Join(filepath.Dir(*cfgPath), cfg.SSHKey)
	}
	// tun.key not shipped? Use the device's own SSH key (auto-generated in
	// %LOCALAPPDATA%\opentunnel on first run and authorized by the panel on
	// approval) — so the exe works fully standalone, no files needed.
	if cfg.SSHKey != "" {
		if _, err := os.Stat(cfg.SSHKey); err != nil {
			if ts, terr := client.NewTokenStore(); terr == nil {
				if _, kerr := ts.EnsureSSHKey(); kerr == nil {
					cfg.SSHKey = ts.SSHPrivatePath()
					fmt.Println("[i] ssh key: using this device's own key (auto-generated)")
				}
			}
		}
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
	fmt.Printf("[i] device: %s\n", device.DeviceName)

	// Graceful stop path: signals (Ctrl+C / window close) or panel decisions
	// (ban) both cancel the context and wake the main loop.
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
	var stopOnce sync.Once
	requestStop := func() {
		stopOnce.Do(func() {
			stopSignals()
		})
	}

	// Register with panel (fire-and-forget; panel will create pending peer)
	safeGo("register", func() { client.RegisterWithPanel(cfg, device) })
	// Background heartbeat and status poll (kick/ban/pending)
	safeGo("poll", func() { client.PollTokenStatus(cfg, device, requestStop) })

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

	fmt.Printf("[i] otu-client %s\n", version.Version)
	safeGo("health", func() {
		client.NewHealthReporter(cfg, device, dialer.Probe).Start(60 * time.Second)
	})
	if cfg.AutoUpdateEnabled() {
		safeGo("update", func() { client.UpdateLoop() })
		fmt.Println("[i] auto-update: watching GitHub releases")
	}

	httpAddr := cfg.HTTPAddr
	socksAddr := cfg.SOCKSAddr
	var lnHTTP, lnSOCKS net.Listener
	warnIfExposed(socksAddr, "socks_addr")
	warnIfExposed(httpAddr, "http_addr")

	if socksAddr != "" {
		lnSOCKS, err = listenRetry("tcp", socksAddr)
		if err != nil {
			portFailExit(socksAddr, err, mgr)
		}
		safeGo("socks", func() { proxy.ServeSOCKS5(ctx, lnSOCKS, dialer, log.Default()) })
		fmt.Printf("[+] SOCKS5     -> %s\n", socksAddr)
	}
	if httpAddr != "" {
		lnHTTP, err = listenRetry("tcp", httpAddr)
		if err != nil {
			portFailExit(httpAddr, err, mgr)
		}
		safeGo("http", func() { proxy.ServeHTTPProxy(ctx, lnHTTP, dialer, log.Default()) })
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

	if doubleClick {
		fmt.Println()
		fmt.Println("================================================================")
		fmt.Println(" otu is running. Your web browser now goes through the tunnel.")
		fmt.Println()
		fmt.Println(" HOW TO USE")
		fmt.Println("   1. Just browse normally - no other setup needed.")
		fmt.Println("   2. First time only: the admin must approve this device,")
		fmt.Println("      then pages load automatically (can take a minute).")
		fmt.Println("   3. This window hides itself in a few seconds and otu keeps")
		fmt.Println("      running in the background. To stop, run stop-otu.bat")
		fmt.Println("      (next to otu-client.exe). Settings restore automatically.")
		fmt.Println("================================================================")
		// Close-proof: hide the console once the banner has been read so an
		// accidental window close can't take the tunnel down.
		safeGo("hide-console", func() {
			time.Sleep(8 * time.Second)
			netenv.HideConsole()
		})
	} else {
		fmt.Println("[i] Point your browser at the SOCKS5 or HTTP proxy above, or press Ctrl+C to stop.")
	}

	<-ctx.Done()
	if lnSOCKS != nil {
		_ = lnSOCKS.Close()
	}
	if lnHTTP != nil {
		_ = lnHTTP.Close()
	}
	fmt.Println("\nbye - settings restored where changed.")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// listenRetry retries binding for a few seconds. After a self-update the
// re-exec'd process can race the exiting one for the proxy ports; retrying
// lets the handover settle instead of crashing the new process.
func listenRetry(network, addr string) (net.Listener, error) {
	var ln net.Listener
	var err error
	for i := 0; i < 20; i++ {
		ln, err = net.Listen(network, addr)
		if err == nil {
			return ln, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, err
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
