package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	panelOnce.Do(func() {
		// Rotation list: configured pins plus everything learned in-band,
		// so the HTTPS fallback survives certificate renewal too.
		fps := cfg.FingerprintSet()
		fps = append(fps, LoadExtraPins()...)
		cl, err := transport.NewPinnedHTTPClient(transport.PinnedHTTPOptions{
			DialAddr:     cfg.DialHostPort(),
			ServerName:   cfg.SNIHost(),
			Fingerprint:  cfg.Fingerprint,
			Fingerprints: fps,
			Insecure:     cfg.Insecure,
			Timeout:      20 * time.Second,
			ChromeHello:  true,
		})
		panelClientBuildErr = err
		if err == nil {
			panelClient = cl
			panelBase = "https://" + cfg.SNIHost()
		}
	})
	if panelClientBuildErr != nil {
		return nil, "", panelClientBuildErr
	}
	return panelClient, panelBase, nil
}

var (
	panelOnce           sync.Once
	panelClient         *http.Client
	panelBase           string
	panelClientBuildErr error
)

func RegisterWithPanel(cfg *config.ClientConf, device *deviceFile) {
	// Fire-and-forget initial registration; retry a few times
	for i := 0; i < 3; i++ {
		if err := doRegister(cfg, device); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
}

func doRegister(cfg *config.ClientConf, device *deviceFile) error {
	cl, base, err := panelHTTP(cfg)
	if err != nil {
		return err
	}
	// Include the device public key: bans bind to the key, not just the
	// token, so a ban cannot be shed by re-registering on the same device.
	pub := ""
	if ts, err := NewTokenStore(); err == nil {
		pub, _ = ts.EnsureSSHKey()
	}
	body, _ := json.Marshal(map[string]string{
		"token": device.Token, "fingerprint": device.Fingerprint, "device_name": device.DeviceName, "ssh_pubkey": pub,
	})
	resp, err := cl.Post(base+"/api/token/request", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 {
		return fmt.Errorf("banned")
	}
	return nil
}

// TokenStatus queries the panel for this device's admission state.
// Startup uses it to distinguish a live ban (grace notice mode) from a
// stale local ban marker left behind by an admin unban.
func TokenStatus(cfg *config.ClientConf, token string) (status, kickReason, banReason, kickExpires string, err error) {
	return checkTokenStatus(cfg, token)
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
	status, kickReason, banReason, kickExpires, err := checkTokenStatus(cfg, device.Token)
	if err != nil {
		return // transient network error — keep the last known state
	}
	if status == *last {
		return
	}
	*last = status
	switch status {
	case "approved":
		fmt.Println("[+] Access granted — this device is online.")
		// An unban that landed while we carry stale local markers (or a
		// pending grace shutdown) takes effect immediately.
		if ts, terr := NewTokenStore(); terr == nil {
			ts.ClearBan()
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
		ts, _ := NewTokenStore()
		ts.WriteHardBan(banReason, "permanent")
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

func checkTokenStatus(cfg *config.ClientConf, token string) (status, kickReason, banReason, kickExpires string, err error) {
	// In-band first: on TLS-intercepting networks pinned HTTPS cannot
	// connect by design, and the authenticated session is the covert
	// path everywhere else too. Servers predating v0.9.23 close the
	// stream, the exchange errors, and we fall through to HTTPS.
	if fn := currentCtrl(); fn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), ctrlTimeout)
		resp, cerr := fn(ctx, protocol.CtrlRequest{Op: "status", Token: token})
		cancel()
		if cerr == nil && resp != nil && resp.OK {
			return resp.Status, resp.KickReason, resp.BanReason, resp.KickExpires, nil
		}
	}
	cl, base, perr := panelHTTP(cfg)
	if perr != nil {
		return "", "", "", "", perr
	}
	var resp *http.Response
	// v0.9.22+: the token moved out of the URL — TLS-intercepting middleboxes
	// decrypt and log the query line, which is where the credential used to
	// ride. POST body first.
	payload, _ := json.Marshal(map[string]string{"token": token})
	resp, err = cl.Post(base+"/api/token/status", "application/json", bytes.NewReader(payload))
	if err == nil && resp.StatusCode != http.StatusOK {
		// Panels predating v0.9.22 answer every POST "not found" (they read
		// the token from the query only). Legacy-GET fallback; the query form
		// survives there until the server is updated.
		_ = resp.Body.Close()
		resp, err = cl.Get(base + "/api/token/status?token=" + token)
	}
	if err != nil {
		return "", "", "", "", err
	}
	defer resp.Body.Close()
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	return res["status"], res["kick_reason"], res["ban_reason"], res["kick_expires"], nil
}
