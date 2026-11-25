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

	"opentunnel/internal/authority"
	"opentunnel/internal/config"
	"opentunnel/internal/panel"
	"opentunnel/internal/panelproxy"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/serverpool"
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
	if cfg.AuthorityURL != "" {
		log.Fatal("a remote relay node cannot start a local panel/database; run otu-panel only at the central authority")
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
	defer panelDB.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	if cfg.AuthorityListen == "" && !cfg.StaticTokenOnly {
		// The local relay and panel already share this key pair. Read it
		// without generating/replacing identity state; if it is unavailable,
		// refuse startup rather than silently trusting or dropping metadata.
		proxyProof, proofErr := panelproxy.Load(cfg.CertFile, cfg.KeyFile)
		if proofErr != nil {
			log.Fatal("panel relay proof identity unavailable")
		}
		ph.WithProxyProof(proxyProof)
	}
	ph, err = ph.WithServerPoolAuthentication(cfg.PoolID, cfg.EnrollmentLogin, cfg.RequireChannelAuth && cfg.PoolID != "")
	if err != nil {
		log.Fatalf("server pool authority: %v", err)
	}
	ph.WithPoolChannelSupport(cfg.InnerTLSCertFile != "" && cfg.InnerTLSKeyFile != "")
	if cfg.AuthorityListen != "" {
		certData, err := privatefile.ReadOnly(cfg.AuthorityCert, 16<<10)
		if err != nil {
			log.Fatal("authority TLS certificate unavailable")
		}
		keyData, err := privatefile.ReadOnly(cfg.AuthorityKey, 16<<10)
		if err != nil {
			log.Fatal("authority TLS private key unavailable")
		}
		pair, err := tls.X509KeyPair(certData, keyData)
		clear(keyData)
		if err != nil {
			log.Fatal("authority TLS identity invalid")
		}
		raw, err := serverpool.ReadDocument(cfg.AuthorityNodes)
		var nodes authority.Nodes
		if err != nil || serverpool.DecodeStrict(raw, &nodes) != nil || nodes.Validate() != nil {
			log.Fatal("authority node inventory invalid; no implicit node trust")
		}
		tlsConfig, err := authority.ServerTLS(pair, nodes)
		if err != nil {
			log.Fatal(err)
		}
		info, err := panelDB.BindServerPoolAuthentication(cfg.PoolID, cfg.EnrollmentLogin, true)
		if err != nil {
			log.Fatal("authority policy mismatch")
		}
		ah, err := authority.NewHandler(panelDB, info, nodes, ph.Handler())
		if err != nil {
			log.Fatal(err)
		}
		srv := &http.Server{Addr: cfg.AuthorityListen, Handler: ah, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		defer srv.Close()
		go func() { <-ctx.Done(); _ = srv.Close() }()
		go func() {
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Print("panel: central authority listener stopped; relay requests will fail closed")
			}
		}()
	}

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

	// One serialized durable reconcile covers approval, revoke, rekey, reaper,
	// missing files and missed hooks. Unknown operator entries are preserved.
	akPath := os.Getenv("OTU_AUTHORIZED_KEYS")
	if akPath == "" {
		akPath = filepath.Join(stateDir, "authorized_keys")
	}
	sshEnabled := cfg.ListenInternal != "" || os.Getenv("OTU_AUTHORIZED_KEYS") != ""
	if info, err := os.Lstat(akPath); err == nil {
		sshEnabled = sshEnabled || info.Mode().IsRegular()
	} else if !os.IsNotExist(err) {
		sshEnabled = true
	}
	if sshEnabled {
		reconcile := func() error { _, err := panelDB.ReconcileSSH(akPath, permitTarget); return err }
		ph.WithSSHReconciler(reconcile)
		if err := reconcile(); err != nil {
			log.Print("panel: managed SSH reconciliation incomplete; durable inventory retained")
		}
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := reconcile(); err != nil {
						log.Print("panel: managed SSH reconciliation incomplete; durable inventory retained")
					}
				}
			}
		}()
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
		<-ctx.Done()
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
		defer tlsSrv.Close()
		go func() { <-ctx.Done(); _ = tlsSrv.Close() }()
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				panelDB.SentinelTick(geo.CountryName)
			}
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
