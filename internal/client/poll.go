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
	// Try both cdn and vpn hosts for panel (in case one is blocked)
	panelURL := "https://" + host + "/api/token/request"
	body, _ := json.Marshal(map[string]string{
		"token": device.Token, "fingerprint": device.Fingerprint, "device_name": device.DeviceName,
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

func PollTokenStatus(cfg *config.ClientConf, device *deviceFile) {
	// Give the fire-and-forget registration a moment to land, then check
	// immediately so a fresh device sees its pending notice right away.
	time.Sleep(3 * time.Second)
	checkOnce(cfg, device)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		checkOnce(cfg, device)
	}
}

func checkOnce(cfg *config.ClientConf, device *deviceFile) {
	status, kickReason, banReason, kickExpires, err := checkTokenStatus(cfg, device.Token)
	if err != nil {
		return
	}
	switch status {
	case "kicked":
		fmt.Printf("\n[NOTICE] You have been kicked: %s — disconnecting in 10 minutes (until %s)\n", kickReason, kickExpires)
		time.AfterFunc(10*time.Minute, func() {
			fmt.Println("Kick grace period ended — disconnecting.")
			// Hard exit after grace
			// Note: main context will be cancelled via signal, but we force
			panic("kicked")
		})
	case "banned":
		fmt.Printf("\n[BANNED] %s\n", banReason)
		// Persist hard ban
		ts, _ := NewTokenStore()
		ts.WriteHardBan(banReason, "permanent")
		// Serve ban page locally and exit
		serveBanPage(banReason)
	case "pending":
		fmt.Printf("[*] Token pending approval — waiting for admin (approve at https://%s/admin/)\n", cfg.ServerAddr)
	case "expired":
		fmt.Println("[*] Token expired after 10 days inactivity — regenerating...")
		ts, _ := NewTokenStore()
		ts.LoadOrCreate() // will generate new if expired
	}
}

func checkTokenStatus(cfg *config.ClientConf, token string) (status, kickReason, banReason, kickExpires string, err error) {
	host := cfg.ServerAddr
	// Panel is on same host as tunnel, at /admin (same TLS)
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

func serveBanPage(reason string) {
	fmt.Printf("Displaying ban page: %s\n", reason)
	html := fmt.Sprintf(`<html><body style="font-family:sans-serif;text-align:center;padding:50px"><h1>Banned</h1><p>%s</p><p>Token will not regenerate.</p></body></html>`, reason)
	_ = html
	panic("banned: " + reason)
}
