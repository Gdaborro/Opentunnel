// otu-server is the opentunnel relay. Run it on a VPS; clients connect over
// TLS+WebSocket and it dials their requested targets. The management plane
// (panel) runs separately as otu-panel; this relay reverse-proxies /admin and
// /api/token to it so heavy tunnel traffic can never starve admin requests.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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

	// Management plane split: the panel runs as its own process (otu-panel)
	// on PanelUpstream. The relay keeps using the same panel DB directly for
	// per-stream decisions (CheckToken/IsBlocked — hot path, cached), and
	// reverse-proxies the /admin and /api/token request trees to the panel
	// process so admin actions stay responsive even under full load.
	panelUpstream := os.Getenv("OTU_PANEL_UPSTREAM")
	if panelUpstream == "" {
		panelUpstream = "http://127.0.0.1:8090"
	}

	// Relay still opens the panel DB: per-token checks, blocklist, traffic
	// accounting and ISP enforcement are enforced here at the data plane.
	stateDirForPanel := os.Getenv("TMPDIR")
	if stateDirForPanel == "" {
		stateDirForPanel = "/var/lib/opentunnel"
	}
	panelDB, err := panel.Open(filepath.Join(stateDirForPanel, "panel.db"), cfg.PurgeAfterDays)
	if err != nil {
		log.Printf("panel db: %v (panel enforcement disabled)", err)
		panelDB = nil
	}

	baseHandler := server.Handler(server.Options{
		Token:                  cfg.Token,
		WSPath:                 cfg.WSPath,
		PanelDB:                panelDB, // nil-safe: legacy mode when panel disabled
		AllowRestrictedTargets: cfg.AllowRestrictedTargets,
		AllowLegacyMaster:      cfg.AllowLegacyMaster,
	})
	var handler http.Handler = baseHandler
	if panelDB != nil {
		target, perr := url.Parse(panelUpstream)
		if perr != nil {
			log.Fatalf("panel upstream: %v", perr)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		origDirector := proxy.Director
		proxy.Director = func(r *http.Request) {
			origDirector(r)
			r.Host = target.Host
		}
		// Keep-alive to the panel process: under load, each proxied request
		// reuses a warm connection instead of paying a fresh loopback TCP
		// setup, keeping admin actions fast when the relay is busy.
		proxy.Transport = &http.Transport{
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			// Panel process down or saturated: serve a plain-text pointer
			// instead of hanging the admin's browser.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "panel process unavailable — retry in a moment; the relay itself is fine\n")
		}
		mux := http.NewServeMux()
		mux.Handle("/admin/", proxy)
		mux.Handle("/admin", proxy)
		mux.Handle("/api/token/", proxy)
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
