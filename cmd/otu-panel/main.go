// otu-panel is the management-plane process: it serves the admin SPA, auth,
// and the public token API on its own listener so the control plane stays
// responsive even when the relay (otu-server) is saturated with traffic.
//
// It shares the panel SQLite database with the relay (WAL mode) and can be
// fronted by the relay's HTTPS endpoint via reverse proxy, or reached
// directly on its own port in emergencies.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
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
	"opentunnel/internal/transport"
	"opentunnel/internal/version"
)

func main() {
	cfgPath := flag.String("c", "server.toml", "server config (shares the relay's settings)")
	listen := flag.String("listen", "127.0.0.1:8090", "panel listener (loopback recommended; front with the relay or TLS)")
	tlsListen := flag.String("tls-listen", "", "optional dedicated TLS listener, e.g. :8444 (serves the ACME cert when available)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("opentunnel panel", version.Version)
		return
	}

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Panel state dir must match the relay's so both open the same DB.
	stateDir := os.Getenv("TMPDIR")
	if stateDir == "" {
		stateDir = "/var/lib/opentunnel"
	}
	panelDB, err := panel.Open(filepath.Join(stateDir, "panel.db"), cfg.PurgeAfterDays)
	if err != nil {
		log.Fatalf("panel db: %v", err)
	}
	auth := panel.NewAuth(panelDB)
	if envUser := os.Getenv("ADMIN_USER"); envUser != "" {
		if envPass := os.Getenv("ADMIN_PASSWORD"); envPass != "" {
			_ = auth.EnsureAdmin(envUser, envPass)
		}
	}
	if auth.NeedsSetup() {
		log.Printf("panel: no admin — visit /admin/setup to create one (one-time)")
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
	// tier's authorized_keys (same logic as the relay's hook).
	ph.WithApproveHook(func(token string) {
		pub := ph.SSHKeyPath(token)
		if pub == "" {
			return
		}
		akPath := os.Getenv("OTU_AUTHORIZED_KEYS")
		if akPath == "" {
			akPath = filepath.Join(stateDir, "authorized_keys")
		}
		if _, err := os.Stat(akPath); err != nil {
			return
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

	srv := &http.Server{
		Addr:              *listen,
		Handler:           ph.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		_ = srv.Close()
	}()

	// Optional dedicated TLS listener for emergencies: presents the ACME
	// certificate from the shared cache (trusted by browsers) or falls back
	// to the pinned self-signed pair.
	if *tlsListen != "" {
		var tlsCfg *tls.Config
		if cfg.AcmeDomain != "" {
			domains := strings.Split(cfg.AcmeDomain, ",")
			for i := range domains {
				domains[i] = strings.TrimSpace(domains[i])
			}
			mgr := &autocert.Manager{
				Cache:      autocert.DirCache(filepath.Join(stateDir, "acme")),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(domains...),
			}
			tlsCfg = mgr.TLSConfig()
			tlsCfg.MinVersion = tls.VersionTLS12
		} else {
			cert, _, cerr := transport.LoadOrCreateCert(cfg.CertFile, cfg.KeyFile, cfg.Host)
			if cerr != nil {
				log.Fatalf("panel tls: %v", cerr)
			}
			tlsCfg = &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*cert},
			}
		}
		tlsSrv := &http.Server{
			Addr:              *tlsListen,
			Handler:           ph.Handler(),
			ReadHeaderTimeout: 15 * time.Second,
			TLSConfig:         tlsCfg,
		}
		go func() {
			log.Printf("panel tls listener on %s", *tlsListen)
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Printf("panel tls: %v", err)
			}
		}()
	}

	log.Printf("otu-panel %s listening on %s", version.Version, *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

func readFileString(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}
