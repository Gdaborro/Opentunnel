// otu-server is the opentunnel relay. Run it on a VPS; clients connect over
// TLS+WebSocket and it dials their requested targets.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*cert},
		},
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		fmt.Println("\nshutting down…")
		_ = srv.Close()
	}()

	log.Printf("otu-server listening on %s", cfg.Listen)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		if err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}
}
