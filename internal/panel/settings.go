package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type settingsRequest struct {
	KillSwitch     *bool     `json:"kill_switch"`
	KillReason     *string   `json:"kill_switch_reason"`
	KillAllow      *[]string `json:"kill_switch_allow"`
	AutoAcceptMin  *int      `json:"auto_accept_minutes"`
	SSHMaxBps      *int64    `json:"ssh_tier_max_bps"`
	SSHDailyMB     *int64    `json:"ssh_tier_daily_mb"`
	SSHTrickleKbps *int64    `json:"ssh_tier_trickle_kbps"`
}

func (h *Handler) apiSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		values, err := h.db.readSettings()
		if err != nil {
			http.Error(w, "policy unavailable", 503)
			return
		}
		allow := []string{}
		for _, token := range strings.Split(values["kill_switch_allow"], ",") {
			if token = strings.TrimSpace(token); token != "" {
				allow = append(allow, token)
			}
		}
		out := map[string]any{"kill_switch": values["kill_switch"] == "1", "kill_switch_reason": values["kill_switch_reason"], "kill_switch_allow": allow,
			"ssh_tier_max_bps": positiveSetting(values["ssh_tier_max_bps"]), "ssh_tier_daily_mb": positiveSetting(values["ssh_tier_daily_mb"]), "ssh_tier_trickle_kbps": positiveSetting(values["ssh_tier_trickle_kbps"]), "auto_accept_active": false}
		if until, err := time.Parse("2006-01-02 15:04:05", values["auto_accept_until"]); err == nil {
			out["auto_accept_until"] = until.Format(time.RFC3339)
			out["auto_accept_active"] = time.Now().Before(until)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	if !requirePOST(w, r) {
		return
	}
	var req settingsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid settings request", 400)
		return
	}
	updates, err := prepareSettings(req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := h.db.SetSettings(updates); err != nil {
		http.Error(w, "policy update unavailable; nothing changed", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// Validate the ENTIRE request before committing any part of it. A bad allowlist
// or rate must not partially change a reason, switch or admission window.
func prepareSettings(req settingsRequest) (map[string]string, error) {
	updates := map[string]string{}
	if req.KillSwitch != nil {
		updates["kill_switch"] = "0"
		if *req.KillSwitch {
			updates["kill_switch"] = "1"
		}
	}
	if req.KillReason != nil {
		v := strings.TrimSpace(*req.KillReason)
		if len(v) > 500 {
			return nil, fmt.Errorf("reason too long (max 500)")
		}
		updates["kill_switch_reason"] = v
	}
	if req.KillAllow != nil {
		if len(*req.KillAllow) > 64 {
			return nil, fmt.Errorf("allowlist too large (max 64)")
		}
		clean := []string{}
		seen := map[string]bool{}
		for _, token := range *req.KillAllow {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			if !validTokenCharset(token) {
				return nil, fmt.Errorf("invalid allowlist token")
			}
			if !seen[token] {
				seen[token] = true
				clean = append(clean, token)
			}
		}
		updates["kill_switch_allow"] = strings.Join(clean, ",")
	}
	for _, limit := range []struct {
		key   string
		value *int64
		max   int64
	}{{"ssh_tier_max_bps", req.SSHMaxBps, 1_000_000_000}, {"ssh_tier_daily_mb", req.SSHDailyMB, 1_000_000}, {"ssh_tier_trickle_kbps", req.SSHTrickleKbps, 1_000_000}} {
		if limit.value != nil {
			if *limit.value < 0 || *limit.value > limit.max {
				return nil, fmt.Errorf("%s out of range", limit.key)
			}
			updates[limit.key] = strconv.FormatInt(*limit.value, 10)
		}
	}
	if req.AutoAcceptMin != nil {
		minutes := *req.AutoAcceptMin
		if minutes < 0 || minutes > 1440 {
			return nil, fmt.Errorf("auto_accept_minutes must be 0..1440")
		}
		updates["auto_accept_until"] = ""
		if minutes > 0 {
			updates["auto_accept_until"] = time.Now().UTC().Add(time.Duration(minutes) * time.Minute).Format("2006-01-02 15:04:05")
		}
	}
	if len(updates) == 0 {
		return nil, fmt.Errorf("at least one policy field is required")
	}
	return updates, nil
}

func (db *DB) readSettings() (map[string]string, error) {
	rows, err := db.Query(`SELECT key,COALESCE(value,'') FROM settings WHERE key IN ('kill_switch','kill_switch_reason','kill_switch_allow','ssh_tier_max_bps','ssh_tier_daily_mb','ssh_tier_trickle_kbps','auto_accept_until')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, rows.Err()
}

func (db *DB) SetSettings(values map[string]string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, values[key]); err != nil {
			return err
		}
	}
	kind := "settings"
	if _, ok := values["kill_switch"]; ok {
		kind = "kill-switch"
	}
	if _, err := tx.Exec(`INSERT INTO events(kind,detail,at) VALUES(?,?,datetime('now'))`, kind, "operator policy updated: "+strings.Join(keys, ", ")); err != nil {
		return err
	}
	if value, ok := values["kill_switch"]; ok {
		severity, message := "info", "kill switch released"
		if value == "1" {
			severity, message = "critical", "KILL SWITCH ENGAGED — operator allowlist applies"
		}
		if _, err := tx.Exec(`INSERT INTO alerts(severity,kind,message) VALUES(?,'kill-switch',?)`, severity, message); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	db.policyMu.Lock()
	db.killAt, db.killDetailAt, db.sshAt = time.Time{}, time.Time{}, time.Time{}
	db.policyMu.Unlock()
	return nil
}
