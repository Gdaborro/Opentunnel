// otu-server is the opentunnel relay. Run it on a VPS; clients connect over
// TLS+WebSocket and it dials their requested targets.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"opentunnel/internal/config"
	"opentunnel/internal/panel"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

func readFileString(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

func main() {
	cfgPath := flag.String("c", "server.toml", "path to server config")
	genConfig := flag.Bool("gen-config", false, "write a template config and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	printFP := flag.Bool("print-fingerprint", false, "load/create certificate and print its SHA-256 fingerprint, then exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("opentunnel server", version.Version)
		return
	}

	cfg, err := config.LoadServer(*cfgPath)
	if *printFP {
		if err != nil {
			log.Fatalf("load config: %v", err)
		}
		_, fp, ferr := transport.LoadOrCreateCert(cfg.CertFile, cfg.KeyFile, cfg.Host)
		if ferr != nil {
			log.Fatalf("certificate: %v", ferr)
		}
		fmt.Println(fp)
		return
	}
	if *genConfig {
		if err := config.WriteServerTemplate(*cfgPath); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("template written to %s\n", *cfgPath)
		return
	}
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	cert, fingerprint, err := transport.LoadOrCreateCert(cfg.CertFile, cfg.KeyFile, cfg.Host)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}

	var tlsCfg *tls.Config
	var acmeDomains []string
	if cfg.AcmeDomain != "" {
		stateDir := os.Getenv("TMPDIR")
		if stateDir == "" {
			stateDir = "."
		}
		// Support comma-separated domains for zero-downtime migration.
		acmeDomains = splitAndTrim(cfg.AcmeDomain)
		mgr := &autocert.Manager{
			Cache:      autocert.DirCache(filepath.Join(stateDir, "acme")),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeDomains...),
		}
		tlsCfg = mgr.TLSConfig()
		tlsCfg.MinVersion = tls.VersionTLS12
		fingerprint = "(managed by Let's Encrypt — fetch with: openssl s_client -connect 127.0.0.1:443 -servername " +
			acmeDomains[0] + " </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout)"
		fmt.Printf("ACME enabled for %v\n", acmeDomains)
	} else {
		tlsCfg = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*cert},
		}
	}
	fmt.Println("========================================================")
	fmt.Printf("  certificate fingerprint (pin this in the client):\n    %s\n", fingerprint)
	fmt.Println("========================================================")

	// Panel DB (same machine, shadcn UI at /admin)
	stateDirForPanel := os.Getenv("TMPDIR")
	if stateDirForPanel == "" {
		stateDirForPanel = "/var/lib/opentunnel"
	}
	panelDB, err := panel.Open(filepath.Join(stateDirForPanel, "panel.db"), cfg.PurgeAfterDays)
	if err != nil {
		log.Printf("panel db: %v (panel disabled)", err)
		panelDB = nil
	}
	var panelHandler http.Handler
	if panelDB != nil {
		auth := panel.NewAuth(panelDB)
		// One-time setup: if ADMIN_USER/PASSWORD env is set, pre-seed it
		// (useful for headless deploys). Otherwise first visitor to
		// /admin/setup creates the admin — after that only that login works.
		if envUser := os.Getenv("ADMIN_USER"); envUser != "" {
			if envPass := os.Getenv("ADMIN_PASSWORD"); envPass != "" {
				_ = auth.EnsureAdmin(envUser, envPass)
			}
		}
		if auth.NeedsSetup() {
			log.Printf("panel: no admin — visit https://%s/admin/setup to create one (one-time)", func() string {
				h := cfg.Host
				if len(acmeDomains) > 0 {
					h = acmeDomains[0]
				}
				if h == "" {
					h = "localhost" + cfg.Listen
				}
				return h
			}())
		}
		geo := panel.OpenGeoIP(cfg.GeoIPDB)
		if cfg.GeoIPDB != "" {
			if geo != nil {
				log.Printf("panel: geoip enabled (%s)", cfg.GeoIPDB)
			} else {
				log.Printf("panel: geoip db %s unreadable — country map disabled", cfg.GeoIPDB)
			}
		}
		ph := panel.New(panelDB, auth, cfg.AutoApprove).WithGeoIP(geo)
		// Approving a device also installs its SSH public key into the ssh
		// tier's authorized_keys, so standalone clients (device-generated
		// keys) can use the fallback tier without shipping tun.key.
		ph.WithApproveHook(func(token string) {
			pub := ph.SSHKeyPath(token)
			if pub == "" {
				return
			}
			akPath := os.Getenv("OTU_AUTHORIZED_KEYS")
			if akPath == "" {
				akPath = "/home/tun/.ssh/authorized_keys"
			}
			if _, err := os.Stat(akPath); err != nil {
				return // no ssh tier on this server — skip silently
			}
			f, err := os.OpenFile(akPath, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				log.Printf("panel: authorize ssh key for %s: %v", token[:8], err)
				return
			}
			defer f.Close()
			if !strings.Contains(readFileString(akPath), strings.TrimSpace(pub)) {
				f.WriteString(strings.TrimSpace(pub) + "\n")
			}
		})
		panelHandler = ph.Handler()
		if cfg.AutoApprove {
			log.Printf("panel: auto_approve enabled — new devices register as approved")
		}
		panelHost := cfg.Host
		if len(acmeDomains) > 0 {
			panelHost = acmeDomains[0]
		}
		if panelHost == "" {
			panelHost = "localhost" + cfg.Listen
		}
		log.Printf("panel enabled at https://%s/admin", panelHost)
	}

	baseHandler := server.Handler(server.Options{
		Token:                  cfg.Token,
		WSPath:                 cfg.WSPath,
		PanelDB:                panelDB, // nil-safe: legacy mode when panel disabled
		AllowRestrictedTargets: cfg.AllowRestrictedTargets,
		AllowLegacyMaster:      cfg.AllowLegacyMaster,
	})
	var handler http.Handler = baseHandler
	if panelHandler != nil {
		mux := http.NewServeMux()
		mux.Handle("/admin/", panelHandler)
		mux.Handle("/admin", panelHandler)
		mux.Handle("/api/token/", panelHandler)
		mux.Handle("/", baseHandler)
		handler = mux
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		TLSConfig:         tlsCfg,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		fmt.Println("\nshutting down…")
		_ = srv.Close()
	}()

	// Optional second listener sharing the same handler and certificate —
	// useful when censors intercept standard web ports but leave other
	// ports untouched.
	if cfg.ListenAlt != "" {
		altLn, lerr := net.Listen("tcp", cfg.ListenAlt)
		if lerr != nil {
			log.Fatalf("alt listen: %v", lerr)
		}
		go func() {
			if aerr := srv.ServeTLS(altLn, "", ""); aerr != nil && aerr != http.ErrServerClosed {
				log.Printf("alt listener: %v", aerr)
			}
		}()
		log.Printf("alt listener on %s", cfg.ListenAlt)
	}

	// Optional PLAIN (no-TLS) WebSocket listener bound to loopback only:
	// the entry point for the ssh transport, where SSH itself provides the
	// outer encryption and opentunnel's AEAD layer provides end-to-end
	// confidentiality.
	if cfg.ListenInternal != "" {
		intLn, ierr := net.Listen("tcp", cfg.ListenInternal)
		if ierr != nil {
			log.Fatalf("internal listen: %v", ierr)
		}
		go func() {
			if ierr := srv.Serve(intLn); ierr != nil && ierr != http.ErrServerClosed {
				log.Printf("internal listener: %v", ierr)
			}
		}()
		log.Printf("internal (plain) listener on %s", cfg.ListenInternal)
	}

	log.Printf("otu-server listening on %s", cfg.Listen)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		if err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
