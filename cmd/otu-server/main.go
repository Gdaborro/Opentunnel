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
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"opentunnel/internal/config"
	"opentunnel/internal/server"
	"opentunnel/internal/transport"
)

// version is stamped at build time via -ldflags "-X main.version=x.y.z".
var version = "dev"

func main() {
	cfgPath := flag.String("c", "server.toml", "path to server config")
	genConfig := flag.Bool("gen-config", false, "write a template config and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	printFP := flag.Bool("print-fingerprint", false, "load/create certificate and print its SHA-256 fingerprint, then exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("opentunnel server", version)
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
	if cfg.AcmeDomain != "" {
		stateDir := os.Getenv("TMPDIR")
		if stateDir == "" {
			stateDir = "."
		}
		mgr := &autocert.Manager{
			Cache:      autocert.DirCache(filepath.Join(stateDir, "acme")),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.AcmeDomain),
		}
		tlsCfg = mgr.TLSConfig()
		tlsCfg.MinVersion = tls.VersionTLS12
		fingerprint = "(managed by Let's Encrypt — fetch with: openssl s_client -connect 127.0.0.1:443 -servername " +
			cfg.AcmeDomain + " </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout)"
		fmt.Printf("ACME enabled for %s\n", cfg.AcmeDomain)
	} else {
		tlsCfg = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*cert},
		}
	}
	fmt.Println("========================================================")
	fmt.Printf("  certificate fingerprint (pin this in the client):\n    %s\n", fingerprint)
	fmt.Println("========================================================")

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: server.Handler(server.Options{
			Token:  cfg.Token,
			WSPath: cfg.WSPath,
		}),
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
