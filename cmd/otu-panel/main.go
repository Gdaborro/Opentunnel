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
	// listener (the ssh tier's direct-tcpip target). Defaults match the
	// relay's listen_internal; custom deployments stay consistent.
	// NOTE: permitlisten="" was tried for the remote-forward direction and
	// REVERTED — sshd's option parser rejects the empty-string form, skips
	// the whole key line and denies the device (production incident
	// 2026-10-28: every school device lost the ssh tier). Remote forwards
	// bind to loopback by default (no GatewayPorts), which is acceptable.
	permitTarget := "127.0.0.1:8081"
	if cfg.ListenInternal != "" {
		permitTarget = cfg.ListenInternal
	}

	// Approving a device installs/refreshes its SSH public key in the ssh
	// tier's authorized_keys. The canonical line carries a forced command
	// (1.0.1, N-11: `restrict` alone still permits non-PTY command
	// execution and SFTP — proven empirically against OpenSSH 10.0) plus
	// least-privilege options: forwarding ONLY to the internal ws
	// listener. The rewrite is idempotent, drops malformed lines it finds,
	// and refuses keys that fail validation outright. Ban and delete
	// remove the key again — N-12: revocation is real.
	akPath := os.Getenv("OTU_AUTHORIZED_KEYS")
	if akPath == "" {
		akPath = filepath.Join(stateDir, "authorized_keys")
	}
	ph.WithApproveHook(func(token string) {
		pub, ok := panel.CanonicalSSHPubKey(ph.SSHKeyPath(token))
		if !ok {
			return
		}
		if _, err := os.Stat(akPath); err != nil {
			return
		}
		if _, err := panel.UpsertAuthorizedKey(akPath, pub, permitTarget); err != nil {
			log.Printf("panel: authorize ssh key for %s: %v", shortLogTok(token), err)
		}
	})
	ph.WithRevokeHook(func(token string) {
		pub, ok := panel.CanonicalSSHPubKey(ph.SSHKeyPath(token))
		if !ok {
			return
		}
		if _, err := os.Stat(akPath); err != nil {
			return
		}
		if _, err := panel.RemoveAuthorizedKey(akPath, pub); err != nil {
			log.Printf("panel: revoke ssh key for %s: %v", shortLogTok(token), err)
		}
	})

	// Startup self-heal (2026-11-05 incident): an approved device whose
	// line is missing from the file the running sshd actually reads can
	// never authenticate — and nothing on the device can distinguish
	// "not approved" from "key lost". Re-add every approved device's key
	// on startup: only ADDS missing lines, never removes, so revocations
	// and operator entries are untouched.
	if _, err := os.Stat(akPath); err == nil {
		if n, err := panel.ReconcileAuthorizedKeys(akPath, permitTarget, panelDB.ApprovedSSHPubKeys()); err != nil {
			log.Printf("panel: authorized_keys reconcile: %v", err)
		} else if n > 0 {
			log.Printf("panel: authorized_keys reconcile: restored %d missing device key(s)", n)
		}
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           ph.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		// 1.0.1: bound reads and writes (slowloris; the login endpoint was
		// unbounded before the body cap landed on it).
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
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

	// Proactive detectors (v1.1.0): travel / IP-spread / registration-burst
	// once a minute. Findings and actions are throttled per subject
	// (persistently — restarts never re-fire), and the tick is a no-op
	// while the response mode is "off" (/admin/api/sentinel).
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			panelDB.SentinelTick(geo.CountryName)
		}
	}()

	log.Printf("otu-panel %s listening on %s", version.Version, *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

// shortLogTok is an 8-char log prefix (device tokens are >=16 chars).
func shortLogTok(t string) string {
	if len(t) > 8 {
		return t[:8]
	}
	return t
}
