// otu-server is the opentunnel relay. Run it on a VPS; clients connect over
// TLS+WebSocket and it dials their requested targets. The management plane
// (panel) runs separately as otu-panel; this relay reverse-proxies /admin and
// /api/token to it so heavy tunnel traffic can never starve admin requests.
package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
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

	// leafFP tracks the CURRENT leaf certificate fingerprint so the
	// in-band control channel can announce it to clients: a fixed pin
	// bricks every client at each Let's Encrypt renewal.
	var leafFP atomic.Value // string (hex)
	leafFP.Store(fingerprint)

	// Pin self-check (CDN front): the certificate clients SEE is the edge's,
	// not necessarily the origin's. When pin_probe_host is set, the relay
	// dials its own public HTTPS endpoint through the CDN on a jittered
	// schedule, learns the client-visible leaf, and announces THAT pin
	// in-band — renewals and edge rotations heal without operator action.
	// While enabled, the direct-serve wrapper below stays off (it would
	// clobber the edge pin with the origin pin).
	if cfg.PinProbeHost != "" {
		probePin := func() {
			conn, derr := tls.Dial("tcp", net.JoinHostPort(cfg.PinProbeHost, "443"), &tls.Config{
				ServerName:         cfg.PinProbeHost,
				InsecureSkipVerify: true, // we only fingerprint the presented leaf
				MinVersion:         tls.VersionTLS12,
			})
			if derr != nil {
				return
			}
			state := conn.ConnectionState()
			_ = conn.Close()
			if len(state.PeerCertificates) > 0 {
				leafFP.Store(hex.EncodeToString(transport.FingerprintCert(state.PeerCertificates[0].Raw)))
			}
		}
		probePin()
		go func() {
			for {
				time.Sleep(30*time.Minute + time.Duration(rand.Int63n(int64(30*time.Minute))))
				probePin()
			}
		}()
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
		transport.RealisticTLS(tlsCfg)
		// Watch every served leaf while no CDN probe is configured: the
		// control channel must always announce the live pin. (With
		// pin_probe_host set, the probe above is the sole authority.)
		if cfg.PinProbeHost == "" {
			if inner := tlsCfg.GetCertificate; inner != nil {
				tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					c, cerr := inner(hello)
					if cerr == nil && c != nil && len(c.Certificate) > 0 {
						leafFP.Store(hex.EncodeToString(transport.FingerprintCert(c.Certificate[0])))
					}
					return c, cerr
				}
			}
		}
		fingerprint = "(managed by Let's Encrypt — fetch with: openssl s_client -connect 127.0.0.1:443 -servername " +
			acmeDomains[0] + " </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout)"
		fmt.Printf("ACME enabled for %v\n", acmeDomains)
	} else {
		tlsCfg = transport.RealisticTLS(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*cert},
		})
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

	baseOpts := server.Options{
		Token:                  cfg.Token,
		WSPath:                 cfg.WSPath,
		AllowRestrictedTargets: cfg.AllowRestrictedTargets,
		AllowLegacyMaster:      cfg.AllowLegacyMaster,
		TrustCloudflareIPs:     cfg.TrustCloudflareIPs,
		CurrentPin:             func() string { v, _ := leafFP.Load().(string); return v },
	}
	if panelDB != nil {
		baseOpts.PanelDB = panelDB
	} // else: leave the interface nil (a typed-nil *DB would defeat the
	// nil checks and crash the relay on first use — legacy static-token
	// mode when the panel is disabled).
	baseHandler := server.Handler(baseOpts)
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
		// Stamp the REAL client IP (TCP peer, or CF-Connecting-IP behind
		// the CDN front) before proxying: the panel's per-IP rate limits
		// and login lockout key on it, and the header overwrites anything
		// the outside sent — unspoofable from beyond the relay.
		stampIP := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Otu-Client-IP", server.ResolveClientIP(r, cfg.TrustCloudflareIPs))
			proxy.ServeHTTP(w, r)
		})
		mux := http.NewServeMux()
		mux.Handle("/admin/", stampIP)
		mux.Handle("/admin", stampIP)
		mux.Handle("/api/token/", stampIP)
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

	// HTTP/3 listener (v0.9.26): same handler mux over QUIC on the UDP
	// side of the port — the transport that survives TLS interception.
	// Optional: a busy/special UDP port just means the h3 tier is absent.
	if _, port, perr := net.SplitHostPort(cfg.Listen); perr == nil {
		udpAddr, uerr := net.ResolveUDPAddr("udp", net.JoinHostPort("", port))
		if uerr == nil {
			if udpConn, ulerr := net.ListenUDP("udp", udpAddr); ulerr == nil {
				h3TLS := tlsCfg.Clone()
				h3TLS.NextProtos = []string{"h3"}
				h3srv := &http3.Server{TLSConfig: h3TLS, Handler: handler}
				go func() {
					log.Printf("h3 (HTTP/3) listener on udp/%s", port)
					if herr := h3srv.Serve(udpConn); herr != nil && herr != http.ErrServerClosed {
						log.Printf("h3 listener: %v", herr)
					}
				}()
			} else {
				log.Printf("h3 listener: udp bind: %v (h3 tier disabled)", ulerr)
			}
		}
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
