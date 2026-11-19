package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
)

// panelHTTP returns the process-wide pinned control-plane client and the
// base URL for panel API calls. Status polls land on the same host as the
// tunnel; a stock Go fingerprint there, beside Chrome-hello tunnel flows,
// is a two-packet confession under TLS interception — so control traffic
// rides the identical pin/parrot stack.
func panelHTTP(cfg *config.ClientConf) (*http.Client, string, error) {
	var err error
	cfg, err = cfg.ControlConfig()
	if err != nil {
		return nil, "", err
	}
	fps := cfg.FingerprintSet()
	if cfg.Pool == nil {
		fps = append(fps, LoadExtraPins()...)
	}
	key := fmt.Sprintf("%s|%s|%s|%t|%s", cfg.IdentityScope(), cfg.DialHostPort(), cfg.ServerAddr, cfg.Insecure, strings.Join(fps, ","))
	panelMu.Lock()
	defer panelMu.Unlock()
	if panelClient != nil && panelKey == key {
		return panelClient, panelBase, nil
	}
	cl, err := transport.NewPinnedHTTPClient(transport.PinnedHTTPOptions{
		DialAddr:     cfg.DialHostPort(),
		ServerName:   cfg.SNIHost(),
		Fingerprint:  cfg.Fingerprint,
		Fingerprints: fps,
		Insecure:     cfg.Insecure,
		Timeout:      20 * time.Second,
		ChromeHello:  true,
	})
	if err != nil {
		return nil, "", err
	}
	if panelClient != nil {
		panelClient.CloseIdleConnections()
	}
	panelClient, panelKey = cl, key
	panelBase = "https://" + cfg.ServerAddr
	return panelClient, panelBase, nil
}

var (
	panelMu     sync.Mutex
	panelKey    string
	panelClient *http.Client
	panelBase   string
	plainOnce   sync.Once
	plainClient *http.Client
)

// plainHTTPClient trusts the system roots. It exists ONLY as the bootstrap
// fallback on TLS-intercepting networks: a fresh device must be able to
// register and watch for its approval there, and until approved it has no
// tunnel to ride. Re-registration cannot hijack an existing identity
// (fingerprint and ssh key are write-once), so the worst case equals the
// pre-v0.9.22 behavior new installs relied on. A LIVE approved token never
// takes this path — see checkTokenStatus.
func plainHTTPClient() *http.Client {
	plainOnce.Do(func() {
		plainClient = &http.Client{Timeout: 20 * time.Second}
	})
	return plainClient
}

func RegisterWithPanel(cfg *config.ClientConf, device *deviceFile) {
	RegisterWithPanelContext(context.Background(), cfg, device)
}

func RegisterWithPanelContext(parent context.Context, cfg *config.ClientConf, device *deviceFile) {
	// Fire-and-forget initial registration; retry a few times
	var finalErr error
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(parent, 20*time.Second)
		err := doRegisterContext(ctx, cfg, device)
		cancel()
		if err == nil {
			return
		}
		finalErr = err
		if parent.Err() != nil {
			return
		}
		if errors.Is(err, errRegistrationIdentityConflict) {
			log.Printf("registration: stored device identity differs; verify the public key in the panel SSH-key recovery page")
			return
		}
		if errors.Is(err, ErrEnrollmentLoginRequired) {
			log.Printf("registration: selected pool requires enrollment login; restart in a terminal (no credentials saved or automatically retried)")
			return
		}
		if !updateWait(parent, 2*time.Second) {
			return
		}
	}
	if finalErr != nil {
		log.Print("registration: no verified enrollment channel available; existing identity retained. Check TLS trust and administrator-assisted enrollment before expecting approval.")
	}
}

func doRegister(cfg *config.ClientConf, device *deviceFile) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return doRegisterContext(ctx, cfg, device)
}

func doRegisterContext(parent context.Context, cfg *config.ClientConf, device *deviceFile) error {
	if err := parent.Err(); err != nil {
		return err
	}
	if cfg.Pool != nil {
		ctx, cancel := context.WithTimeout(parent, 15*time.Second)
		defer cancel()
		return EnrollPool(ctx, cfg, device, nil)
	}
	ts, err := NewTokenStore()
	if err != nil {
		return err
	}
	pub, err := ts.EnsureSSHKey()
	if err != nil {
		return err // never announce a missing/stale public-key cache
	}
	body, _ := json.Marshal(map[string]string{
		"token": device.Token, "fingerprint": device.Fingerprint, "device_name": device.DeviceName, "ssh_pubkey": pub,
	})
	post := func(cl *http.Client, url string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(parent, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return cl.Do(req)
	}
	// Bootstrap identity substitution remains possible through system-trusted
	// intercepted TLS, even before the token is approved. Production defaults
	// therefore require pinned TLS or an explicitly managed authenticated carrier.
	if cl, base, err := panelHTTP(cfg); err == nil {
		if resp, perr := post(cl, base+"/api/token/request"); perr == nil {
			defer resp.Body.Close()
			return registrationResponse(resp)
		}
	}
	if cfg.CarrierSOCKS != "" && cfg.Pool == nil {
		cl, base, err := carrierHTTP(cfg)
		if err != nil {
			return err
		}
		defer cl.CloseIdleConnections()
		resp, err := post(cl, base+"/api/token/request")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return registrationResponse(resp)
	}
	if !plainBootstrapAllowed(cfg, device, ts) {
		return errors.New("registration requires a verified channel; use pinned TLS, a managed authenticated carrier or administrator-assisted enrollment")
	}
	log.Printf("WARNING: untrusted bootstrap explicitly enabled; administrator must independently verify this device's public key")
	resp, err := post(plainHTTPClient(), "https://"+cfg.SNIHost()+"/api/token/request")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return registrationResponse(resp)
}

// plainBootstrapAllowed limits system-trusted token registration to the same
// process that minted an identity. Existing device state, including an
// unreadable approval marker, must use pinned or in-band verification instead.
func plainBootstrapAllowed(cfg *config.ClientConf, device *deviceFile, ts *TokenStore) bool {
	return cfg.AllowUntrustedBootstrap && device.Created && !ts.EverApproved(device.Fingerprint)
}

var errRegistrationIdentityConflict = errors.New("registration identity conflict")

func registrationResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		return nil
	case http.StatusConflict:
		return errRegistrationIdentityConflict
	case http.StatusForbidden:
		return errors.New("registration forbidden")
	default:
		return fmt.Errorf("registration returned HTTP %d", resp.StatusCode)
	}
}

// TokenStatus queries the panel for this device's admission state.
// Startup uses it to distinguish a live ban (grace notice mode) from a
// stale local ban marker left behind by an admin unban. No plain-HTTPS
// fallback here: at startup the device may be approved, and a live token
// must never cross an intercepting middlebox.
func TokenStatus(cfg *config.ClientConf, token string) (status, kickReason, banReason, kickExpires string, err error) {
	status, kickReason, banReason, kickExpires, _, err = checkTokenStatus(cfg, token, false)
	return
}

// PollTokenStatus watches the panel for admission changes (approval, kick,
// ban, purge) and prints plain-language notices on state transitions. stop
// requests a clean shutdown; onBan fires instead of stop for bans so the
// client can show the ban notice everywhere for a grace period first
// (nil onBan keeps the old instant-stop behavior); onApproved fires on
// transitions back to approved so a pending grace shutdown can be cancelled
// (nil onApproved is fine).
func PollTokenStatus(cfg *config.ClientConf, device *deviceFile, stop func(), onBan func(reason string), onApproved func()) {
	PollTokenStatusContext(context.Background(), cfg, device, stop, onBan, onApproved)
}

func PollTokenStatusContext(ctx context.Context, cfg *config.ClientConf, device *deviceFile, stop func(), onBan func(string), onApproved func()) {
	// Give the fire-and-forget registration a moment to land, then check
	// immediately so a fresh device sees its pending notice right away.
	// Afterwards the cadence is jittered (metronomic beacons to one host
	// are correlatable); hostile networks stretch it further.
	if !updateWait(ctx, 3*time.Second) {
		return
	}
	last := ""
	checkOnceContext(ctx, cfg, device, stop, onBan, onApproved, &last)
	for {
		if !updateWait(ctx, jittered(15*time.Second)) {
			return
		}
		checkOnceContext(ctx, cfg, device, stop, onBan, onApproved, &last)
	}
}

func checkOnce(cfg *config.ClientConf, device *deviceFile, stop func(), onBan func(reason string), onApproved func(), last *string) {
	checkOnceContext(context.Background(), cfg, device, stop, onBan, onApproved, last)
}

func checkOnceContext(ctx context.Context, cfg *config.ClientConf, device *deviceFile, stop func(), onBan func(string), onApproved func(), last *string) {
	if ctx.Err() != nil {
		return
	}
	// Bootstrap states may ride the system-trusted fallback (fresh and
	// pending devices behind TLS interception have no pinned channel and
	// no tunnel yet, and their token grants nothing until approved). An
	// approved device's token is a live credential: it never takes the
	// plain path — in-band and pinned only. The gate consults the durable
	// ever-approved marker (fingerprint-keyed), not just this process's
	// memory: on the first poll after startup, `last` is empty for every
	// device, and an approved one must not leak its token on the first
	// iteration (audit round three, N-1 Window B).
	everApproved := false
	if ts, terr := NewPoolTokenStore(cfg.IdentityScope()); terr == nil {
		everApproved = ts.EverApproved(device.Fingerprint)
	}
	previousStatus := strings.TrimSuffix(*last, ":unverified")
	bootstrap := device.Created && !everApproved && (previousStatus == "" || previousStatus == "pending" || previousStatus == "expired")
	bootstrap = bootstrap && cfg.AllowUntrustedBootstrap
	status, kickReason, banReason, kickExpires, trusted, err := checkTokenStatusContext(ctx, cfg, device.Token, bootstrap)
	if err != nil || ctx.Err() != nil {
		return // transient network error — keep the last known state
	}
	decision := status
	if !trusted {
		decision += ":unverified"
	}
	if decision == *last && status != "" {
		return
	}
	*last = decision // a later trusted approval must not be hidden by an unverified one
	if ts, terr := NewPoolTokenStore(cfg.IdentityScope()); terr == nil {
		// Durable approval marker (fingerprint-keyed): from now on this
		// device's token never crosses a system-trusted channel again,
		// across restarts and re-registrations.
		//
		// 1.0.1 (N-2): only a TRUSTED channel may write durable state. A
		// plain (system-roots) response is display-only — a MITM
		// answering "approved" must not flip the ever-approved marker
		// and strand onboarding, and a forged "banned" must not persist
		// a hard ban across restarts.
		if status == "approved" && trusted {
			if err := ts.MarkApproved(device.Fingerprint); err != nil {
				// This device now has an existing identity on the next start.
				// Close plain bootstrap immediately and for every later run;
				// an approval-marker write failure must never reopen it.
				device.Created = false
				log.Printf("approval marker persistence failed; plain bootstrap disabled: %v", err)
			}
		}
	}
	switch status {
	case "approved":
		if trusted {
			fmt.Println("[+] Administrator approval verified. Tunnel transport and browser-policy checks still apply.")
		} else {
			fmt.Println("[!] Unverified bootstrap response reports approval; not proof of a working or trusted tunnel.")
		}
		// An unban that landed while we carry stale local markers (or a
		// pending grace shutdown) takes effect immediately. Cleared only
		// on a trusted verdict (1.0.1, N-2): an intercepting middlebox
		// must not be able to lift a real ban's local marker.
		if trusted {
			if ts, terr := NewPoolTokenStore(cfg.IdentityScope()); terr == nil {
				ts.ClearBan()
			}
		}
		if trusted && onApproved != nil {
			onApproved()
		}
	case "pending":
		fmt.Println("[*] Waiting for one-time approval from the network administrator.")
		fmt.Println("    Nothing to do here — you'll be connected automatically once approved.")
	case "kicked":
		if kickExpires != "" {
			fmt.Printf("[!] Access paused: %s\n    Resumes automatically at %s (server time).\n", kickReason, kickExpires)
		} else {
			fmt.Printf("[!] Access paused: %s\n", kickReason)
		}
	case "banned":
		// The session-level notice applies either way (a real ban must be
		// visible immediately), but the DURABLE marker waits for a
		// trusted verdict (1.0.1, N-2): a forged plain-channel "banned"
		// used to brick the next start with os.Exit(1).
		if trusted {
			if ts, terr := NewPoolTokenStore(cfg.IdentityScope()); terr == nil {
				ts.WriteHardBan(banReason, "permanent")
			}
		}
		if onBan != nil {
			onBan(banReason)
		} else {
			stop()
		}
	case "expired":
		fmt.Println("[*] Registration expired — re-registering for approval...")
		_ = doRegisterContext(ctx, cfg, device)
	case "":
		// Panel no longer knows this token (purged after inactivity):
		// re-register and wait for re-approval.
		fmt.Println("[*] Device no longer registered — re-registering for approval...")
		_ = doRegisterContext(ctx, cfg, device)
	}
}

// checkTokenStatus resolves a token's state. The trusted return reports
// whether the answer came from a cryptographically anchored channel
// (in-band session or pinned HTTPS): only those may drive DURABLE local
// state — plain bootstrap answers are display-only (1.0.1, N-2).
func checkTokenStatus(cfg *config.ClientConf, token string, allowPlainFallback bool) (status, kickReason, banReason, kickExpires string, trusted bool, err error) {
	return checkTokenStatusContext(context.Background(), cfg, token, allowPlainFallback)
}

func checkTokenStatusContext(parent context.Context, cfg *config.ClientConf, token string, allowPlainFallback bool) (status, kickReason, banReason, kickExpires string, trusted bool, err error) {
	if err := parent.Err(); err != nil {
		return "", "", "", "", false, err
	}
	if cfg.Pool != nil {
		if err := cfg.Pool.Verify(time.Now()); err != nil {
			return "", "", "", "", false, err
		}
		if _, err := requirePoolIdentity(cfg.IdentityScope(), token); err != nil {
			return "", "", "", "", false, err
		}
	}
	// In-band first: on TLS-intercepting networks pinned HTTPS cannot
	// connect by design, and the authenticated session is the covert
	// path everywhere else too. Servers predating v0.9.23 close the
	// stream, the exchange errors, and we fall through to HTTPS.
	if fn := currentPoolCtrl(cfg.IdentityScope()); fn != nil {
		ctx, cancel := context.WithTimeout(parent, ctrlTimeout)
		resp, cerr := fn(ctx, protocol.CtrlRequest{Op: "status", Token: token})
		cancel()
		if cerr == nil && resp != nil && resp.OK {
			return resp.Status, resp.KickReason, resp.BanReason, resp.KickExpires, true, nil
		}
	}
	if err := parent.Err(); err != nil {
		return "", "", "", "", false, err
	}
	var pinnedErr error
	if cl, base, perr := panelHTTP(cfg); perr == nil {
		st, kr, br, ke, ferr := fetchStatusScopedContext(parent, cl, base, token, cfg.Pool == nil, cfg.IdentityScope())
		if ferr == nil {
			return st, kr, br, ke, true, nil
		}
		pinnedErr = ferr
	} else {
		pinnedErr = perr
	}
	if cfg.CarrierSOCKS != "" && cfg.Pool == nil {
		cl, base, cerr := carrierHTTP(cfg)
		if cerr == nil {
			defer cl.CloseIdleConnections()
			st, kr, br, ke, err := fetchStatusScopedContext(parent, cl, base, token, false, "")
			if err == nil {
				return st, kr, br, ke, true, nil
			}
			pinnedErr = err
		} else {
			pinnedErr = cerr
		}
	}
	if allowPlainFallback && cfg.Pool == nil {
		// Bootstrap fallback (see checkOnce): system-trusted TLS so a
		// new device can register and learn its approval on intercepted
		// networks. The token is not yet a live credential here — and
		// the legacy query-GET form is never used on this path (the
		// token would ride the URL line straight into proxy logs).
		st, kr, br, ke, ferr := fetchStatusScopedContext(parent, plainHTTPClient(), "https://"+cfg.SNIHost(), token, false, "")
		return st, kr, br, ke, false, ferr
	}
	return "", "", "", "", false, pinnedErr
}

// fetchStatus asks the panel for a token's admission state over the given
// client: POST body (v0.9.22+). The legacy query-GET fallback applies only
// to the PINNED channel against panels predating body parsing; the plain
// client never puts the token in a URL.
func fetchStatus(cl *http.Client, base, token string, allowLegacyGet bool) (status, kickReason, banReason, kickExpires string, err error) {
	return fetchStatusScoped(cl, base, token, allowLegacyGet, "")
}

func fetchStatusScoped(cl *http.Client, base, token string, allowLegacyGet bool, scope string) (status, kickReason, banReason, kickExpires string, err error) {
	return fetchStatusScopedContext(context.Background(), cl, base, token, allowLegacyGet, scope)
}

func fetchStatusScopedContext(parent context.Context, cl *http.Client, base, token string, allowLegacyGet bool, scope string) (status, kickReason, banReason, kickExpires string, err error) {
	if err := parent.Err(); err != nil {
		return "", "", "", "", err
	}
	payload, _ := json.Marshal(map[string]string{"token": token})
	req, err := http.NewRequestWithContext(parent, http.MethodPost, base+"/api/token/status", bytes.NewReader(payload))
	if err != nil {
		return "", "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if scope != "" {
		allowLegacyGet = false
		if err := SignPoolHTTPRequest(req, payload, scope); err != nil {
			return "", "", "", "", err
		}
	}
	resp, err := cl.Do(req)
	if err == nil && allowLegacyGet && resp.StatusCode != http.StatusOK {
		// Panels predating v0.9.22 answer every POST "not found" (they
		// read the token from the query only). Legacy-GET fallback; the
		// query form survives there until the server is updated.
		_ = resp.Body.Close()
		legacy, reqErr := http.NewRequestWithContext(parent, http.MethodGet, base+"/api/token/status?token="+token, nil)
		if reqErr != nil {
			return "", "", "", "", reqErr
		}
		resp, err = cl.Do(legacy)
	}
	if err != nil {
		return "", "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", "", "", "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", "", "", fmt.Errorf("control status returned HTTP %d", resp.StatusCode)
	}
	var res map[string]string
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		return "", "", "", "", errors.New("control status response oversized or incomplete")
	}
	if scope != "" {
		var result struct {
			Status      string `json:"status"`
			KickReason  string `json:"kick_reason"`
			BanReason   string `json:"ban_reason"`
			KickExpires string `json:"kick_expires"`
		}
		if err := serverpool.DecodeStrict(raw, &result); err != nil {
			return "", "", "", "", err
		}
		res = map[string]string{"status": result.Status, "kick_reason": result.KickReason, "ban_reason": result.BanReason, "kick_expires": result.KickExpires}
	} else if err := json.Unmarshal(raw, &res); err != nil {
		return "", "", "", "", errors.New("control status response is invalid")
	}
	switch res["status"] {
	case "approved", "pending", "expired", "banned", "kicked":
	default:
		return "", "", "", "", errors.New("control status response has an unknown verdict")
	}
	return res["status"], res["kick_reason"], res["ban_reason"], res["kick_expires"], nil
}
