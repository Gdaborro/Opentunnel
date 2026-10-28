// otu-panel is the management-plane process: it serves the admin SPA, auth,
// and the public token API on its own listener so the control plane stays
// responsive even when the relay (otu-server) is saturated with traffic.
//
// It shares the panel SQLite database with the relay (WAL mode) and can be
// fronted by the relay's HTTPS endpoint via reverse proxy, or reached
// directly on its own port in emergencies.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
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

	// permitopen pins device-key forwarding to the relay's internal ws
	// listener (the ssh tier's direct-tcpip target); permitlisten="" denies
	// remote forwards entirely (the client never uses -R). Defaults match
	// the relay's listen_internal; custom deployments stay consistent.
	permitTarget := "127.0.0.1:8081"
	if cfg.ListenInternal != "" {
		permitTarget = cfg.ListenInternal
	}

	// Approving a device installs/refreshes its SSH public key in the ssh
	// tier's authorized_keys with least-privilege options: no
	// shell/exec/pty/agent/X11, forwarding ONLY to the internal ws
	// listener, no remote forwards. The rewrite is idempotent and heals
	// legacy rows: a bare or stale-option line for the same key is
	// replaced with the current canonical form (audit rounds two/three).
	ph.WithApproveHook(func(token string) {
		pub := strings.TrimSpace(ph.SSHKeyPath(token))
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
		canonical := `restrict,port-forwarding,permitopen="` + permitTarget + `",permitlisten="" ` + pub
		content := readFileString(akPath)
		if strings.Contains(content, canonical) {
			return // already current
		}
		lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		replaced := false
		for i, l := range lines {
			if strings.Contains(l, pub) {
				lines[i] = canonical
				replaced = true
			}
		}
		if !replaced {
			lines = append(lines, canonical)
		}
		out := strings.Join(lines, "\n") + "\n"
		tmp := akPath + ".tmp"
		if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil || os.Rename(tmp, akPath) != nil {
			_ = os.Remove(tmp)
			log.Printf("panel: authorize ssh key for %s: write failed", token[:8])
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
	// to the pinned self-signed pair. READ-ONLY on the cache (audit round
	// three): running a second autocert Manager here raced the relay's
	// renewer on one LE account — duplicate issuances risk the weekly
	// rate limit and a renewal lockout. The relay is the sole renewer; the
	// panel just serves whatever chain the cache holds.
	if *tlsListen != "" {
		var tlsCfg *tls.Config
		if cfg.AcmeDomain != "" {
			domains := strings.Split(cfg.AcmeDomain, ",")
			for i := range domains {
				domains[i] = strings.TrimSpace(domains[i])
			}
			acmeDir := filepath.Join(stateDir, "acme")
			var cachedCert atomic.Pointer[tls.Certificate]
			var cachedAt atomic.Int64
			loadCert := func() (*tls.Certificate, error) {
				if c := cachedCert.Load(); c != nil && time.Since(time.Unix(cachedAt.Load(), 0)) < 6*time.Hour {
					return c, nil
				}
				data, err := autocert.DirCache(acmeDir).Get(context.Background(), domains[0])
				if err != nil {
					if c := cachedCert.Load(); c != nil {
						return c, nil // stale beats nothing on the emergency listener
					}
					return nil, err
				}
				cert, err := tls.X509KeyPair(data, data)
				if err != nil {
					return nil, err
				}
				cachedCert.Store(&cert)
				cachedAt.Store(time.Now().Unix())
				return &cert, nil
			}
			tlsCfg = transport.RealisticTLS(&tls.Config{
				MinVersion: tls.VersionTLS12,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return loadCert()
				},
			})
		} else {
			cert, _, cerr := transport.LoadOrCreateCert(cfg.CertFile, cfg.KeyFile, cfg.Host)
			if cerr != nil {
				log.Fatalf("panel tls: %v", cerr)
			}
			tlsCfg = transport.RealisticTLS(&tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*cert},
			})
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
