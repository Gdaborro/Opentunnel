// otu-server is the opentunnel relay. Run it on a VPS; clients connect over
// TLS+WebSocket and it dials their requested targets. The management plane
// (panel) runs separately as otu-panel; this relay reverse-proxies /admin and
// /api/token to it to reduce control-plane coupling under tunnel load.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
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

	"opentunnel/internal/authority"
	"opentunnel/internal/config"
	"opentunnel/internal/metrics"
	"opentunnel/internal/panel"
	"opentunnel/internal/panelproxy"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/server"
	"opentunnel/internal/serverpool"
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
	if cfg.AuthorityListen != "" {
		log.Fatal("authority-only panel configuration cannot start a relay; use a separate node configuration/identity")
	}
	lifetime, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	cert, fingerprint, err := transport.LoadOrCreateCert(cfg.CertFile, cfg.KeyFile, cfg.Host)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	var innerCertificate *tls.Certificate
	if cfg.InnerTLSCertFile != "" {
		certData, err := privatefile.ReadOnly(cfg.InnerTLSCertFile, 16<<10)
		if err != nil {
			log.Fatal("inner TLS certificate unavailable")
		}
		keyData, err := privatefile.ReadOnly(cfg.InnerTLSKeyFile, 16<<10)
		if err != nil {
			log.Fatal("inner TLS private key unavailable")
		}
		pair, err := tls.X509KeyPair(certData, keyData)
		clear(keyData)
		if err != nil {
			log.Fatal("inner TLS keypair invalid")
		}
		innerCertificate = &pair
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			log.Fatal("inner TLS leaf invalid")
		}
		log.Printf("inner TLS identity public-key pin: %s", protocol.PublicKeyPin(leaf))
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
	// refreshH3Cert reloads the h3 listener's certificate from the ACME
	// cache (set below once the cache dir is known); the pin probe's
	// cadence keeps it current across renewals.
	var refreshH3Cert atomic.Pointer[func()]
	if cfg.PinProbeHost != "" {
		probePin := func() {
			// Standard chain verification against the host's system roots
			// (audit round four): an on-path attacker or DNS spoofer who
			// redirects this dial cannot obtain a publicly-trusted
			// certificate for the probe hostname — ACME validates from
			// clean resolvers — so only a genuinely-validated leaf may
			// move the pin the whole fleet learns in-band. On failure the
			// previous pin is kept and the problem is logged loudly.
			fp, derr := probeVerifiedLeaf(net.JoinHostPort(cfg.PinProbeHost, "443"), cfg.PinProbeHost, nil)
			if derr != nil {
				log.Printf("pin probe: %s failed verification (%v) — keeping previous pin", cfg.PinProbeHost, derr)
				return
			}
			leafFP.Store(fp)
			if refresh := refreshH3Cert.Load(); refresh != nil {
				(*refresh)()
			}
		}
		probePin()
		go func() {
			for {
				timer := time.NewTimer(30*time.Minute + time.Duration(rand.Int63n(int64(30*time.Minute))))
				select {
				case <-lifetime.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				probePin()
			}
		}()
	}

	var tlsCfg *tls.Config
	var acmeDomains []string
	var acmeDir string
	if cfg.AcmeDomain != "" {
		stateDir := os.Getenv("TMPDIR")
		if stateDir == "" {
			stateDir = "."
		}
		// Support comma-separated domains for zero-downtime migration.
		acmeDomains = splitAndTrim(cfg.AcmeDomain)
		acmeDir = filepath.Join(stateDir, "acme")
		mgr := &autocert.Manager{
			Cache:      autocert.DirCache(acmeDir),
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
	var panelDB *panel.DB
	var policyDB server.PolicyDB
	var central *authority.Client
	var poolInfo serverpool.Info
	if cfg.AuthorityURL != "" {
		certData, err := privatefile.ReadOnly(cfg.AuthorityClientCert, 16<<10)
		if err != nil {
			log.Fatal("authority node certificate unavailable")
		}
		keyData, err := privatefile.ReadOnly(cfg.AuthorityClientKey, 16<<10)
		if err != nil {
			log.Fatal("authority node private key unavailable")
		}
		pair, err := tls.X509KeyPair(certData, keyData)
		clear(keyData)
		if err != nil {
			log.Fatal("authority node TLS identity invalid")
		}
		central, err = authority.NewClient(authority.ClientOptions{URL: cfg.AuthorityURL, PoolID: cfg.PoolID, AuthorityID: cfg.AuthorityID, NodeID: cfg.AuthorityNodeID, Certificate: pair, Pins: cfg.AuthorityPins})
		if err != nil {
			log.Fatalf("central authority configuration: %v", err)
		}
		defer central.Close()
		poolInfo, err = central.Info(context.Background())
		if err != nil || poolInfo.LoginRequired != cfg.EnrollmentLogin {
			log.Fatal("central approval/accounting authority unavailable or policy mismatch; local database fallback refused")
		}
		policyDB = central
	} else if !cfg.StaticTokenOnly {
		panelDB, err = panel.Open(filepath.Join(stateDirForPanel, "panel.db"), cfg.PurgeAfterDays)
		if err != nil {
			log.Fatalf("panel policy database unavailable; refusing to disable enforcement: %v", err)
		}
		defer panelDB.Close()
		poolInfo, err = panelDB.BindServerPoolAuthentication(cfg.PoolID, cfg.EnrollmentLogin, cfg.RequireChannelAuth && cfg.PoolID != "")
		if err != nil {
			log.Fatalf("server pool authority: %v", err)
		}
		policyDB = panelDB
	}
	metricsCtx, stopMetrics := context.WithCancel(lifetime)
	defer stopMetrics()

	baseOpts := server.Options{
		PoolID: cfg.PoolID, AuthorityID: poolInfo.AuthorityID,
		InnerTLSCertificate:    innerCertificate,
		RequireInnerTLS:        cfg.RequireInnerTLS,
		RequireChannelAuth:     cfg.RequireChannelAuth,
		Token:                  cfg.Token,
		WSPath:                 cfg.WSPath,
		AllowRestrictedTargets: cfg.AllowRestrictedTargets,
		AllowStreamingHTTP2:    cfg.AllowStreamingHTTP2,
		AllowLegacyMaster:      cfg.AllowLegacyMaster,
		TrustCloudflareIPs:     cfg.TrustCloudflareIPs,
		RequireV5After:         cfg.RequireV5Time(),
		CurrentPin:             func() string { v, _ := leafFP.Load().(string); return v },
		SSHPublicHost:          cfg.SSHPublicHost,
	}
	if policyDB != nil {
		baseOpts.PanelDB = policyDB
	} // else: leave the interface nil (a typed-nil *DB would defeat the
	// nil checks and crash the relay on first use — legacy static-token
	// mode when the panel is disabled).
	// Sentinel (v1.1.0): one instance shared by the relay handlers and the
	// HTTP error log (scanner intel); pre-seeding here makes Handler() use
	// this one instead of lazily creating its own.
	sntl := baseOpts.EnsureSentinel()
	if policyDB != nil {
		metricStore := policyDB.(interface{ RecordRelayMetrics(metrics.Snapshot) error })
		capture := func() metrics.Snapshot {
			snapshot := metrics.Capture(version.Version)
			snapshot.GuardDroppedSources = baseOpts.GuardInstance().DroppedSources()
			snapshot.SentinelDroppedSubjects, snapshot.SentinelDroppedThrottles, snapshot.SentinelSaturatedEvents = sntl.CapacityCounters()
			return snapshot
		}
		_ = metricStore.RecordRelayMetrics(capture())
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-metricsCtx.Done():
					return
				case <-ticker.C:
					_ = metricStore.RecordRelayMetrics(capture())
				}
			}
		}()
	}
	baseHandler := server.Handler(baseOpts)
	var handler http.Handler = baseHandler
	if central != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/token/", func(w http.ResponseWriter, r *http.Request) {
			central.ForwardPublic(w, r, server.ResolveClientIP(r, cfg.TrustCloudflareIPs))
		})
		mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
		mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
		mux.Handle("/", baseHandler)
		handler = mux // node public routes never expose the authority's admin API
	} else if panelDB != nil {
		proxyProof, proofErr := panelproxy.New(cert.PrivateKey)
		if proofErr != nil {
			log.Fatal("panel proxy proof unavailable; forwarded metadata would fail closed")
		}
		target, perr := url.Parse(panelUpstream)
		if perr != nil {
			log.Fatalf("panel upstream: %v", perr)
		}
		stampIP := newPanelProxy(target, cfg.TrustCloudflareIPs, proxyProof)
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
		// 1.0.1: bound slow request bodies too (slowloris on the proxied
		// admin/token trees). WebSocket upgrades hijack before this
		// applies, so tunnel sessions are unaffected.
		ReadTimeout: 60 * time.Second,
		TLSConfig:   tlsCfg,
		// v1.1.0: TLS handshake errors double as scanner intel — forward
		// them to the sentinel (tlserr.go) while keeping journal parity.
		ErrorLog: log.New(server.SentinelLogWriter(sntl, os.Stderr), "", 0),
	}

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
	// confidentiality. It gets its own http.Server so its requests can be
	// marked as ssh ingress (server.WithIngress): the relay's containment
	// policy (sustained cap + daily budget, sshtier.go) keys on that
	// marker to keep fanned-in ssh traffic from reading as a media relay.
	var intSrv *http.Server
	if cfg.ListenInternal != "" {
		intLn, ierr := net.Listen("tcp", cfg.ListenInternal)
		if ierr != nil {
			log.Fatalf("internal listen: %v", ierr)
		}
		intSrv = &http.Server{
			Handler:           server.WithIngress(handler, server.IngressSSH),
			ReadHeaderTimeout: 15 * time.Second,
			ReadTimeout:       60 * time.Second,
		}
		go func() {
			if ierr := intSrv.Serve(intLn); ierr != nil && ierr != http.ErrServerClosed {
				log.Printf("internal listener: %v", ierr)
			}
		}()
		log.Printf("internal (plain) listener on %s", cfg.ListenInternal)
	}
	var carrierSrv *http.Server
	if cfg.ListenCarrierInternal != "" {
		ln, err := net.Listen("tcp", cfg.ListenCarrierInternal)
		if err != nil {
			log.Fatalf("carrier internal listen: %v", err)
		}
		// No administrative routes on this opt-in fixed-target ingress.
		// The external carrier must independently confine its traffic to
		// this target; Go cannot validate another process's routing rules.
		carrierHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/token/") {
				handler.ServeHTTP(w, r)
			} else {
				baseHandler.ServeHTTP(w, r)
			}
		})
		carrierSrv = &http.Server{Handler: server.WithIngress(carrierHandler, server.IngressCarrier), ReadHeaderTimeout: 15 * time.Second, ReadTimeout: 60 * time.Second}
		go func() {
			if err := carrierSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("carrier ingress: %v", err)
			}
		}()
		log.Printf("managed carrier (loopback-only) ingress on %s", cfg.ListenCarrierInternal)
	}

	go func() {
		<-lifetime.Done()
		fmt.Println("\nshutting down…")
		_ = srv.Close()
		if intSrv != nil {
			_ = intSrv.Close()
		}
		if carrierSrv != nil {
			_ = carrierSrv.Close()
		}
	}()

	// HTTP/3 listener (v0.9.26): same handler mux over QUIC on the UDP
	// side of the port — the transport that survives TLS interception.
	// The h3 TLS config serves the CURRENT ECDSA chain directly: autocert
	// picks its RSA cert for some hellos (quic-go's included), and QUIC
	// clients pin the chain the TCP listener serves — serving the RSA
	// twin breaks their pins. Refreshed alongside the pin probe.
	if host, port, perr := net.SplitHostPort(cfg.Listen); perr == nil && (cfg.H3 == nil || *cfg.H3) {
		if udpAddr, uerr := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port)); uerr == nil {
			if udpConn, ulerr := net.ListenUDP("udp", udpAddr); ulerr == nil {
				var h3Cert atomic.Pointer[tls.Certificate]
				loadH3Cert := func() {
					if acmeDir == "" || len(acmeDomains) == 0 {
						return
					}
					// The autocert cache entry is a combined PEM: private
					// key block first, then the certificate chain (the
					// format autocert itself parses in cacheGet).
					data, cerr := autocert.DirCache(acmeDir).Get(context.Background(), acmeDomains[0])
					if cerr != nil {
						return
					}
					cert, kerr := tls.X509KeyPair(data, data)
					if kerr != nil {
						log.Printf("h3: certificate reload failed: %v", kerr)
						return
					}
					h3Cert.Store(&cert)
					log.Printf("h3: certificate loaded (%s)", acmeDomains[0])
				}
				refreshH3Cert.Store(&loadH3Cert)
				h3TLS := tlsCfg.Clone()
				h3TLS.NextProtos = []string{"h3"}
				if acmeDir != "" {
					// Bypass autocert's hello-driven ECDSA/RSA selection:
					// the h3 path always serves the pinned, current ECDSA
					// chain (the one the TCP listener and every client pin).
					h3TLS.GetConfigForClient = nil
					h3TLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
						if c := h3Cert.Load(); c != nil {
							return c, nil
						}
						return nil, errors.New("h3: certificate not loaded yet")
					}
					loadH3Cert()
				} // static-cert deployments serve tlsCfg.Certificates as-is
				h3srv := &http3.Server{TLSConfig: h3TLS, Handler: handler}
				defer h3srv.Close()
				defer udpConn.Close()
				go func() { <-lifetime.Done(); _ = h3srv.Close(); _ = udpConn.Close() }()
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

type panelProxyRejection struct {
	status int
	cause  error
}

func (e *panelProxyRejection) Error() string { return e.cause.Error() }
func (e *panelProxyRejection) Unwrap() error { return e.cause }

type panelProxyRejectionKey struct{}

type panelProxyTransport struct {
	base http.RoundTripper
}

func (t panelProxyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if rejection, ok := r.Context().Value(panelProxyRejectionKey{}).(*panelProxyRejection); ok {
		return nil, rejection
	}
	return t.base.RoundTrip(r)
}

// newPanelProxy authenticates the exact outgoing request after the Director's
// path rewrite. A failed handoff is rejected, never demoted to direct loopback
// identity at the panel.
func newPanelProxy(target *url.URL, trustCloudflare bool, proof *panelproxy.Proof) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = target.Host
		if err := stampPanelProxyRequest(r, proof); err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, panelproxy.ErrInvalidMetadata) {
				status = http.StatusBadRequest
			} else if errors.Is(err, panelproxy.ErrBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			rejection := &panelProxyRejection{status: status, cause: err}
			*r = *r.WithContext(context.WithValue(r.Context(), panelProxyRejectionKey{}, rejection))
		}
	}
	// Keep-alive to the panel process: under load, each proxied request
	// reuses a warm connection instead of paying a fresh loopback TCP setup.
	proxy.Transport = panelProxyTransport{base: &http.Transport{
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		var rejection *panelProxyRejection
		if errors.As(err, &rejection) && rejection.status != http.StatusServiceUnavailable {
			http.Error(w, "panel proxy request rejected", rejection.status)
			return
		}
		// Panel process down or saturated: serve a plain-text pointer instead
		// of hanging the admin's browser. Proof failures also remain a 503.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "panel process unavailable — retry in a moment; the relay itself is fine\n")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := preparePanelProxyRequest(r, trustCloudflare); err != nil {
			http.Error(w, "invalid panel proxy metadata", http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// preparePanelProxyRequest overwrites client-supplied forwarding metadata.
// Strip client-named hop-by-hop headers first so ReverseProxy cannot delete
// the new stamps after the Director returns.
func preparePanelProxyRequest(r *http.Request, trustCloudflare bool) error {
	server.SanitizeConnectionHeaders(r.Header)
	forwarded := panelproxy.Forwarded{ClientIP: server.ResolveClientIP(r, trustCloudflare), Scheme: "http", Host: r.Host}
	if r.TLS != nil {
		forwarded.Scheme = "https"
	}
	r.Header.Del(panelproxy.ProofHeader)
	r.Header.Set(panelproxy.ClientIPHeader, forwarded.ClientIP)
	r.Header.Set(panelproxy.OriginalHostHeader, forwarded.Host)
	r.Header.Set(panelproxy.SchemeHeader, forwarded.Scheme)
	return panelproxy.ValidateMetadata(forwarded)
}

// stampPanelProxyRequest runs after Director path rewriting. The original
// browser-facing host is already preserved in its own header, so replacing
// r.Host with the panel upstream does not change the authenticated CSRF value.
func stampPanelProxyRequest(r *http.Request, proof *panelproxy.Proof) error {
	return proof.Stamp(r, r.Header.Get(panelproxy.ClientIPHeader), r.Header.Get(panelproxy.SchemeHeader), r.Header.Get(panelproxy.OriginalHostHeader))
}

// probeVerifiedLeaf dials addr with FULL TLS verification (chain against
// roots — nil = system roots — plus hostname match), returning the leaf
// fingerprint hex. The h3-cert refresh and in-band pin announcement run
// only on verified results: an unverified probe would let an on-path
// attacker poison the fleet's trust set (audit round four).
func probeVerifiedLeaf(addr, serverName string, roots *x509.CertPool) (string, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	})
	if err != nil {
		return "", err
	}
	state := conn.ConnectionState()
	_ = conn.Close()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("probe: no certificates presented")
	}
	return hex.EncodeToString(transport.FingerprintCert(state.PeerCertificates[0].Raw)), nil
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
