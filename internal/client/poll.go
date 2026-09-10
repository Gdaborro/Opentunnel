package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"opentunnel/internal/config"
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
	host := cfg.ServerAddr
	panelURL := "https://" + host + "/api/token/request"
	// Include the device public key: bans bind to the key, not just the
	// token, so a ban cannot be shed by re-registering on the same device.
	pub := ""
	if ts, err := NewTokenStore(); err == nil {
		pub, _ = ts.EnsureSSHKey()
	}
	body, _ := json.Marshal(map[string]string{
		"token": device.Token, "fingerprint": device.Fingerprint, "device_name": device.DeviceName, "ssh_pubkey": pub,
	})
	resp, err := http.Post(panelURL, "application/json", bytes.NewReader(body))
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
	host := cfg.ServerAddr
	panelURL := "https://" + host
	resp, err := http.Get(panelURL + "/api/token/status?token=" + token)
	if err != nil {
		return "", "", "", "", err
	}
	defer resp.Body.Close()
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	return res["status"], res["kick_reason"], res["ban_reason"], res["kick_expires"], nil
}
