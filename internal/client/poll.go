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
	"opentunnel/internal/transport"
)

// panelHTTP returns the process-wide pinned control-plane client and the
// base URL for panel API calls. Status polls land on the same host as the
// tunnel; a stock Go fingerprint there, beside Chrome-hello tunnel flows,
// is a two-packet confession under TLS interception — so control traffic
// rides the identical pin/parrot stack.
func panelHTTP(cfg *config.ClientConf) (*http.Client, string, error) {
	fps := append(cfg.FingerprintSet(), LoadExtraPins()...)
	key := fmt.Sprintf("%s|%s|%t|%s", cfg.DialHostPort(), cfg.SNIHost(), cfg.Insecure, strings.Join(fps, ","))
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
	// Fire-and-forget initial registration; retry a few times
	for i := 0; i < 3; i++ {
		err := doRegister(cfg, device)
		if err == nil {
			break
		}
		if errors.Is(err, errRegistrationIdentityConflict) {
			log.Printf("registration: stored device identity differs; verify the public key in the panel SSH-key recovery page")
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func doRegister(cfg *config.ClientConf, device *deviceFile) error {
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
	// Bootstrap identity substitution remains possible through system-trusted
	// intercepted TLS, even before the token is approved. Production defaults
	// therefore require pinned TLS or an explicitly managed authenticated carrier.
	if cl, base, err := panelHTTP(cfg); err == nil {
		if resp, perr := cl.Post(base+"/api/token/request", "application/json", bytes.NewReader(body)); perr == nil {
			defer resp.Body.Close()
			return registrationResponse(resp)
		}
	}
	if cfg.CarrierSOCKS != "" {
		cl, base, err := carrierHTTP(cfg)
		if err != nil {
			return err
		}
		defer cl.CloseIdleConnections()
		resp, err := cl.Post(base+"/api/token/request", "application/json", bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return registrationResponse(resp)
	}
	if !cfg.AllowUntrustedBootstrap || ts.EverApproved(device.Fingerprint) {
		return errors.New("registration requires a verified channel; use pinned TLS, a managed authenticated carrier or administrator-assisted enrollment")
	}
	log.Printf("WARNING: untrusted bootstrap explicitly enabled; administrator must independently verify this device's public key")
	resp, err := plainHTTPClient().Post("https://"+cfg.SNIHost()+"/api/token/request", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return registrationResponse(resp)
}

var errRegistrationIdentityConflict = errors.New("registration identity conflict")

func registrationResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
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
	// Give the fire-and-forget registration a moment to land, then check
	// immediately so a fresh device sees its pending notice right away.
	// Afterwards the cadence is jittered (metronomic beacons to one host
	// are correlatable); hostile networks stretch it further.
	time.Sleep(3 * time.Second)
	last := ""
	checkOnce(cfg, device, stop, onBan, onApproved, &last)
	for {
		time.Sleep(jittered(15 * time.Second))
		checkOnce(cfg, device, stop, onBan, onApproved, &last)
	}
}

func checkOnce(cfg *config.ClientConf, device *deviceFile, stop func(), onBan func(reason string), onApproved func(), last *string) {
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
	if ts, terr := NewTokenStore(); terr == nil {
		everApproved = ts.EverApproved(device.Fingerprint)
	}
	bootstrap := !everApproved && (*last == "" || *last == "pending" || *last == "expired")
	bootstrap = bootstrap && cfg.AllowUntrustedBootstrap
	status, kickReason, banReason, kickExpires, trusted, err := checkTokenStatus(cfg, device.Token, bootstrap)
	if err != nil {
		return // transient network error — keep the last known state
	}
	if status == *last {
		return
	}
	*last = status
	if ts, terr := NewTokenStore(); terr == nil {
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
			ts.MarkApproved(device.Fingerprint)
		}
	}
	switch status {
	case "approved":
		fmt.Println("[+] Access granted — this device is online.")
		// An unban that landed while we carry stale local markers (or a
		// pending grace shutdown) takes effect immediately. Cleared only
		// on a trusted verdict (1.0.1, N-2): an intercepting middlebox
		// must not be able to lift a real ban's local marker.
		if trusted {
			if ts, terr := NewTokenStore(); terr == nil {
				ts.ClearBan()
			}
		}
		if onApproved != nil {
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
			if ts, terr := NewTokenStore(); terr == nil {
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
		_ = doRegister(cfg, device)
	case "":
		// Panel no longer knows this token (purged after inactivity):
		// re-register and wait for re-approval.
		fmt.Println("[*] Device no longer registered — re-registering for approval...")
		_ = doRegister(cfg, device)
	}
}

// checkTokenStatus resolves a token's state. The trusted return reports
// whether the answer came from a cryptographically anchored channel
// (in-band session or pinned HTTPS): only those may drive DURABLE local
// state — plain bootstrap answers are display-only (1.0.1, N-2).
func checkTokenStatus(cfg *config.ClientConf, token string, allowPlainFallback bool) (status, kickReason, banReason, kickExpires string, trusted bool, err error) {
	// In-band first: on TLS-intercepting networks pinned HTTPS cannot
	// connect by design, and the authenticated session is the covert
	// path everywhere else too. Servers predating v0.9.23 close the
	// stream, the exchange errors, and we fall through to HTTPS.
	if fn := currentCtrl(); fn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ctrlTimeout)
		resp, cerr := fn(ctx, protocol.CtrlRequest{Op: "status", Token: token})
		cancel()
		if cerr == nil && resp != nil && resp.OK {
			return resp.Status, resp.KickReason, resp.BanReason, resp.KickExpires, true, nil
		}
	}
	var pinnedErr error
	if cl, base, perr := panelHTTP(cfg); perr == nil {
		st, kr, br, ke, ferr := fetchStatus(cl, base, token, true)
		if ferr == nil {
			return st, kr, br, ke, true, nil
		}
		pinnedErr = ferr
	} else {
		pinnedErr = perr
	}
	if cfg.CarrierSOCKS != "" {
		cl, base, cerr := carrierHTTP(cfg)
		if cerr == nil {
			defer cl.CloseIdleConnections()
			st, kr, br, ke, err := fetchStatus(cl, base, token, false)
			if err == nil {
				return st, kr, br, ke, true, nil
			}
			pinnedErr = err
		} else {
			pinnedErr = cerr
		}
	}
	if allowPlainFallback {
		// Bootstrap fallback (see checkOnce): system-trusted TLS so a
		// new device can register and learn its approval on intercepted
		// networks. The token is not yet a live credential here — and
		// the legacy query-GET form is never used on this path (the
		// token would ride the URL line straight into proxy logs).
		st, kr, br, ke, ferr := fetchStatus(plainHTTPClient(), "https://"+cfg.SNIHost(), token, false)
		return st, kr, br, ke, false, ferr
	}
	return "", "", "", "", false, pinnedErr
}

// fetchStatus asks the panel for a token's admission state over the given
// client: POST body (v0.9.22+). The legacy query-GET fallback applies only
// to the PINNED channel against panels predating body parsing; the plain
// client never puts the token in a URL.
func fetchStatus(cl *http.Client, base, token string, allowLegacyGet bool) (status, kickReason, banReason, kickExpires string, err error) {
	payload, _ := json.Marshal(map[string]string{"token": token})
	resp, err := cl.Post(base+"/api/token/status", "application/json", bytes.NewReader(payload))
	if err == nil && allowLegacyGet && resp.StatusCode != http.StatusOK {
		// Panels predating v0.9.22 answer every POST "not found" (they
		// read the token from the query only). Legacy-GET fallback; the
		// query form survives there until the server is updated.
		_ = resp.Body.Close()
		resp, err = cl.Get(base + "/api/token/status?token=" + token)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&res); err != nil {
		return "", "", "", "", errors.New("control status response is invalid")
	}
	switch res["status"] {
	case "approved", "pending", "expired", "banned", "kicked":
	default:
		return "", "", "", "", errors.New("control status response has an unknown verdict")
	}
	return res["status"], res["kick_reason"], res["ban_reason"], res["kick_expires"], nil
}
