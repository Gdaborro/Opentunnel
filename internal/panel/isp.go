package panel

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// categoryLists are the built-in domain categories an admin can enable as
// whole-group blocks (suffix-matched like single blocklist entries).
var categoryLists = map[string][]string{
	"social": {
		"facebook.com", "instagram.com", "tiktok.com", "twitter.com", "x.com",
		"snapchat.com", "reddit.com", "threads.net", "whatsapp.com",
		"telegram.org", "discord.com", "pinterest.com", "tumblr.com",
	},
	"streaming": {
		"youtube.com", "netflix.com", "twitch.tv", "disneyplus.com",
		"hulu.com", "primevideo.com", "spotify.com", "soundcloud.com",
		"vimeo.com", "dailymotion.com",
	},
	"adult": {
		"pornhub.com", "xvideos.com", "xhamster.com", "xnxx.com",
		"redtube.com", "youporn.com", "brazzers.com",
	},
	"ads": {
		"doubleclick.net", "googlesyndication.com", "googleadservices.com",
		"adnxs.com", "criteo.com", "taboola.com", "outbrain.com",
		"facebook.net", "scorecardresearch.com",
	},
	"gambling": {
		"bet365.com", "sportsbet.com.au", "tab.com.au", "ladbrokes.com",
		"pokerstars.com", "unibet.com",
	},
	// extensions holds domains backing community browser/app extensions
	// (lyrics providers, extension registries). Off by default: blocking
	// these breaks the extensions outright, so it is opt-in per network.
	"extensions": {
		"socalifornian.live",
	},
}

// CategoryNames returns the built-in category names (sorted-ish stable order).
func CategoryNames() []string {
	return []string{"social", "streaming", "adult", "ads", "gambling", "extensions"}
}

// blockCache caches the blocklist + enabled-category suffixes so IsBlocked
// (called per stream) does not hit SQLite every time.
type blockCache struct {
	mu       sync.Mutex
	suffixes []string
	loaded   time.Time
}

const blockCacheTTL = 3 * time.Second

// blockedSuffixes returns all blocked suffixes: explicit blocklist entries
// plus domains from enabled categories.
func (db *DB) blockedSuffixes() []string {
	db.block.mu.Lock()
	defer db.block.mu.Unlock()
	if time.Since(db.block.loaded) < blockCacheTTL && db.block.suffixes != nil {
		return db.block.suffixes
	}
	out := []string{}
	rows, err := db.Query(`SELECT domain FROM blocklist`)
	if err == nil {
		for rows.Next() {
			var d string
			if rows.Scan(&d) == nil {
				if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
					out = append(out, d)
				}
			}
		}
		rows.Close()
	}
	enabled := map[string]bool{}
	rows, err = db.Query(`SELECT category FROM blocked_categories WHERE enabled=1`)
	if err == nil {
		for rows.Next() {
			var c string
			if rows.Scan(&c) == nil {
				enabled[c] = true
			}
		}
		rows.Close()
	}
	for cat, list := range categoryLists {
		if enabled[cat] {
			out = append(out, list...)
		}
	}
	db.block.suffixes = out
	db.block.loaded = time.Now()
	return out
}

// invalidateBlockCache forces a reload on the next IsBlocked call (used
// after blocklist/category changes).
func (db *DB) invalidateBlockCache() {
	db.block.mu.Lock()
	db.block.loaded = time.Time{}
	db.block.mu.Unlock()
}

// BlockWhy names the rule that blocks a domain: the entry's own reason
// when the admin gave one, "blocklist" for plain custom entries, or the
// matching category ("ads category"), "" when allowed. The relay sends this
// to the client so the block page can state the reason instead of just the
// domain.
func (db *DB) BlockWhy(domain string) string {
	if db == nil {
		return ""
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	match := func(d string) bool {
		return domain == d || strings.HasSuffix(domain, "."+d)
	}
	rows, err := db.Query(`SELECT domain, reason FROM blocklist`)
	if err == nil {
		for rows.Next() {
			var d, reason string
			if rows.Scan(&d, &reason) == nil {
				if d = strings.ToLower(strings.TrimSpace(d)); d != "" && match(d) {
					rows.Close()
					if reason = strings.TrimSpace(reason); reason != "" {
						return reason
					}
					return "blocklist"
				}
			}
		}
		rows.Close()
	}
	enabled := map[string]bool{}
	rows, err = db.Query(`SELECT category FROM blocked_categories WHERE enabled=1`)
	if err == nil {
		for rows.Next() {
			var c string
			if rows.Scan(&c) == nil {
				enabled[c] = true
			}
		}
		rows.Close()
	}
	for _, cat := range CategoryNames() {
		if !enabled[cat] {
			continue
		}
		for _, d := range categoryLists[cat] {
			if match(d) {
				return cat + " category"
			}
		}
	}
	return ""
}

// Categories lists all categories with their enabled state and size.
func (db *DB) Categories() []map[string]any {
	enabled := map[string]bool{}
	rows, err := db.Query(`SELECT category, enabled FROM blocked_categories`)
	if err == nil {
		for rows.Next() {
			var c string
			var e int
			if rows.Scan(&c, &e) == nil {
				enabled[c] = e == 1
			}
		}
		rows.Close()
	}
	out := []map[string]any{}
	for _, name := range CategoryNames() {
		out = append(out, map[string]any{
			"category": name,
			"enabled":  enabled[name],
			"domains":  len(categoryLists[name]),
		})
	}
	return out
}

// SetCategoryEnabled toggles a built-in category block.
func (db *DB) SetCategoryEnabled(category string, enabled bool) bool {
	if _, ok := categoryLists[category]; !ok {
		return false
	}
	v := 0
	if enabled {
		v = 1
	}
	if _, err := db.Exec(`INSERT INTO blocked_categories(category,enabled) VALUES(?,?) ON CONFLICT(category) DO UPDATE SET enabled=excluded.enabled`, category, v); err != nil {
		return false
	}
	db.invalidateBlockCache()
	return true
}

// Setting reads a settings key ("" when unset, or when there is no DB).
func (db *DB) Setting(key string) string {
	if db == nil {
		return ""
	}
	var v string
	db.QueryRow(`SELECT COALESCE(value,'') FROM settings WHERE key=?`, key).Scan(&v)
	return v
}

// SetSetting writes a settings key. ssh-tier policy keys bypass their
// read cache immediately so operator changes take effect on the next
// stream instead of up to a second later.
func (db *DB) SetSetting(key, value string) {
	db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if strings.HasPrefix(key, "ssh_tier_") {
		db.invalidateSSHTierCache()
	}
	if strings.HasPrefix(key, "kill_switch") {
		db.policyMu.Lock()
		db.killAt, db.killDetailAt = time.Time{}, time.Time{}
		db.policyMu.Unlock()
	}
}

// KillSwitch reports whether all tunnel traffic is suspended.
func (db *DB) KillSwitch() bool {
	if db == nil {
		return false
	}
	db.policyMu.Lock()
	defer db.policyMu.Unlock()
	if time.Since(db.killAt) < time.Second {
		return db.killOn
	}
	var value string
	err := db.QueryRow(`SELECT COALESCE((SELECT value FROM settings WHERE key='kill_switch'),'0')`).Scan(&value)
	// Boolean-only legacy consumers also fail closed on a read failure.
	// Relay consumers use AccessPolicy, which reports the error explicitly.
	db.killOn = err != nil || (value != "" && value != "0")
	db.killAt = time.Now()
	return db.killOn
}

// SetKillSwitch toggles the global kill switch.
func (db *DB) SetKillSwitch(on bool) {
	v := "0"
	if on {
		v = "1"
	}
	db.SetSetting("kill_switch", v)
}

func (db *DB) killDetail() (string, map[string]bool) {
	if db == nil {
		return "", nil
	}
	db.policyMu.Lock()
	defer db.policyMu.Unlock()
	if time.Since(db.killDetailAt) < time.Second && db.killAllow != nil {
		return db.killReason, db.killAllow
	}
	reason := db.Setting("kill_switch_reason")
	allow := map[string]bool{}
	for _, t := range strings.Split(db.Setting("kill_switch_allow"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			allow[t] = true
		}
	}
	db.killReason, db.killAllow, db.killDetailAt = reason, allow, time.Now()
	return reason, allow
}

// KillSwitchReason returns the admin's reason shown on the client's
// traffic-down page ("" when unset).
func (db *DB) KillSwitchReason() string { r, _ := db.killDetail(); return r }

// KillSwitchAllow reports whether a token keeps tunneling while the kill
// switch is engaged (the operator's own devices).
func (db *DB) KillSwitchAllow(token string) bool {
	_, allow := db.killDetail()
	return allow[token]
}

// KillSwitchAllowList returns the allowlist for the admin API/UI.
func (db *DB) KillSwitchAllowList() []string {
	_, allow := db.killDetail()
	out := make([]string, 0, len(allow))
	for t := range allow {
		out = append(out, t)
	}
	return out
}

// ssh-tier containment policy (relay side: internal/server/sshtier.go): a
// sustained bytes/sec cap and a per-device daily byte budget for ssh
// ingress, plus the post-budget trickle rate. Same 1s cache shape as the
// kill switch — the relay reads it per stream start.
// defaultSSHTrickleBps ≈ 200 kbps: once the daily ssh budget is spent,
// pages keep loading and video cannot hold a buffer.
const defaultSSHTrickleBps = 25_000

// SSHTierLimits returns the ssh-tier containment policy (0 = unset):
// maxBps caps sustained ssh-ingress bandwidth per device, dailyBytes is
// the per-device daily budget on that ingress, and trickleBps is the
// rate new streams degrade to once the budget is spent (defaults to
// ~200 kbps whenever a budget is configured).
func (db *DB) SSHTierLimits() (maxBps, dailyBytes, trickleBps int64) {
	if db == nil {
		return 0, 0, 0
	}
	db.policyMu.Lock()
	defer db.policyMu.Unlock()
	if time.Since(db.sshAt) < time.Second {
		return db.sshMax, db.sshDaily, db.sshTrickle
	}
	maxBps = positiveSetting(db.Setting("ssh_tier_max_bps"))
	mb := positiveSetting(db.Setting("ssh_tier_daily_mb"))
	if mb > 1_000_000 { // cap at 1 TB/day so the shift stays sane
		mb = 1_000_000
	}
	dailyBytes = mb << 20
	trickleBps = positiveSetting(db.Setting("ssh_tier_trickle_kbps")) * 1000 / 8
	if dailyBytes > 0 && trickleBps <= 0 {
		trickleBps = defaultSSHTrickleBps
	}
	db.sshMax, db.sshDaily, db.sshTrickle, db.sshAt = maxBps, dailyBytes, trickleBps, time.Now()
	return maxBps, dailyBytes, trickleBps
}

// invalidateSSHTierCache forces the next SSHTierLimits call to reload.
func (db *DB) invalidateSSHTierCache() {
	db.policyMu.Lock()
	db.sshAt = time.Time{}
	db.policyMu.Unlock()
}

// positiveSetting parses a non-negative integer setting ("" or invalid → 0).
func positiveSetting(v string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// AutoAcceptUntil returns the current auto-accept deadline (zero when off).
func (db *DB) AutoAcceptUntil() time.Time {
	raw := db.Setting("auto_accept_until")
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02 15:04:05", raw)
	if err != nil {
		return time.Time{}
	}
	return t
}

// SetAutoAccept opens (minutes > 0) or closes (minutes <= 0) the auto-accept
// window: while open, new devices are approved instantly on registration.
func (db *DB) SetAutoAccept(minutes int) time.Time {
	if minutes <= 0 {
		db.SetSetting("auto_accept_until", "")
		return time.Time{}
	}
	until := time.Now().UTC().Add(time.Duration(minutes) * time.Minute)
	db.SetSetting("auto_accept_until", until.Format("2006-01-02 15:04:05"))
	return until
}

// AutoAcceptActive reports whether the auto-accept window is currently open.
func (db *DB) AutoAcceptActive() bool {
	until := db.AutoAcceptUntil()
	return !until.IsZero() && time.Now().UTC().Before(until)
}

// PeerLimits returns the configured per-device caps (0 = unlimited).
func (db *DB) PeerLimits(token string) (maxBps, quotaBytes int64) {
	if db == nil {
		return 0, 0
	}
	db.QueryRow(`SELECT COALESCE(max_bps,0), COALESCE(quota_bytes,0) FROM peers WHERE token=?`, token).Scan(&maxBps, &quotaBytes)
	return
}

// SetPeerLimits stores per-device caps and schedule.
func (db *DB) SetPeerLimits(token, schedule string, maxBps, quotaBytes int64) {
	db.Exec(`UPDATE peers SET schedule=?, max_bps=?, quota_bytes=? WHERE token=?`, schedule, maxBps, quotaBytes, token)
}

// SetPeerIP records the last seen source IP for a device (GeoIP in panel)
// and appends a history row for the sentinel's travel analysis (v1.1.0):
// one row per IP change, capped at 200 rows per device and pruned to seven
// days by the reaper.
func (db *DB) SetPeerIP(token, ip string) {
	if db == nil || token == "" || ip == "" {
		return
	}
	// A forwarded loopback source is not a device location. Do not replace
	// usable attribution with the relay's own forwarding socket.
	if addr := net.ParseIP(ip); addr == nil || addr.IsLoopback() {
		return
	}
	db.Exec(`UPDATE peers SET last_ip=? WHERE token=?`, ip, token)
	var last string
	db.QueryRow(`SELECT COALESCE(ip,'') FROM peer_ips WHERE token=? ORDER BY rowid DESC LIMIT 1`, token).Scan(&last)
	if last == ip {
		return
	}
	db.Exec(`INSERT INTO peer_ips(token, ip) VALUES(?,?)`, token, ip)
	db.Exec(`DELETE FROM peer_ips WHERE token=? AND rowid NOT IN
		(SELECT rowid FROM peer_ips WHERE token=? ORDER BY rowid DESC LIMIT 200)`, token, token)
}

// scheduleWindow is one allowed daily interval (minutes since midnight).
type scheduleWindow struct{ start, end int }

// parseSchedule parses the schedule field:
//
//	""                      always allowed
//	"0800-1800"             daily window
//	"0800-1200,1300-1800"   multiple daily windows
//	"Mon-Fri 0800-1800"     weekday range + window(s)
//	"Sat,Sun 1000-1600"     explicit days + window(s)
//
// Malformed schedules fail open (always allowed) so a typo cannot lock a
// device out permanently; the panel validates on save.
func parseSchedule(s string) (days map[time.Weekday]bool, wins []scheduleWindow) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	dayPart, winPart := "", s
	if i := strings.IndexAny(s, " \t"); i > 0 && !isHHMM(strings.TrimSpace(s[:i])) {
		dayPart = strings.TrimSpace(s[:i])
		winPart = strings.TrimSpace(s[i+1:])
	}
	if dayPart != "" {
		days = parseDays(dayPart)
		if days == nil {
			return nil, nil // malformed → fail open
		}
	}
	for _, w := range strings.Split(winPart, ",") {
		parts := strings.Split(strings.TrimSpace(w), "-")
		if len(parts) != 2 {
			return nil, nil
		}
		a, ok1 := parseHHMM(parts[0])
		b, ok2 := parseHHMM(parts[1])
		if !ok1 || !ok2 {
			return nil, nil
		}
		wins = append(wins, scheduleWindow{a, b})
	}
	if len(wins) == 0 {
		return nil, nil
	}
	return days, wins
}

func isHHMM(s string) bool {
	_, ok := parseHHMM(s)
	return ok
}

func parseHHMM(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 4 {
		return 0, false
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[2:])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

var dayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

func parseDays(s string) map[time.Weekday]bool {
	days := map[time.Weekday]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if r := strings.SplitN(part, "-", 2); len(r) == 2 {
			a, ok1 := dayNames[strings.TrimSpace(r[0])]
			b, ok2 := dayNames[strings.TrimSpace(r[1])]
			if !ok1 || !ok2 {
				return nil
			}
			for d := a; ; d = (d + 1) % 7 {
				days[d] = true
				if d == b {
					break
				}
			}
		} else if d, ok := dayNames[part]; ok {
			days[d] = true
		} else {
			return nil
		}
	}
	if len(days) == 0 {
		return nil
	}
	return days
}

// scheduleAllows reports whether now is inside the schedule.
func scheduleAllows(s string, now time.Time) bool {
	days, wins := parseSchedule(s)
	if wins == nil {
		return true
	}
	if days != nil && !days[now.Weekday()] {
		return false
	}
	m := now.Hour()*60 + now.Minute()
	for _, w := range wins {
		if w.start <= w.end {
			if m >= w.start && m < w.end {
				return true
			}
		} else if m >= w.start || m < w.end { // overnight window
			return true
		}
	}
	return false
}

// nextScheduleStart returns when the schedule next allows traffic.
func nextScheduleStart(s string, now time.Time) time.Time {
	days, wins := parseSchedule(s)
	if wins == nil {
		return now
	}
	for i := 0; i < 8; i++ {
		day := now.AddDate(0, 0, i)
		if days != nil && !days[day.Weekday()] {
			continue
		}
		best := -1
		m := now.Hour()*60 + now.Minute()
		for _, w := range wins {
			if i == 0 {
				if w.start <= w.end {
					if m < w.start && (best == -1 || w.start < best) {
						best = w.start
					}
				} else if m < w.start && m >= w.end && (best == -1 || w.start < best) {
					best = w.start
				}
			} else if best == -1 || w.start < best {
				best = w.start
			}
		}
		if best >= 0 {
			return time.Date(day.Year(), day.Month(), day.Day(), best/60, best%60, 0, 0, now.Location())
		}
	}
	return now.Add(24 * time.Hour)
}

// ValidateSchedule reports whether a schedule string parses to real windows.
func ValidateSchedule(s string) bool {
	if strings.TrimSpace(s) == "" {
		return true
	}
	_, wins := parseSchedule(s)
	return wins != nil
}
