package panel

import (
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
}

// CategoryNames returns the built-in category names (sorted-ish stable order).
func CategoryNames() []string {
	return []string{"social", "streaming", "adult", "ads", "gambling"}
}

// blockCache caches the blocklist + enabled-category suffixes so IsBlocked
// (called per stream) does not hit SQLite every time.
type blockCache struct {
	mu       sync.Mutex
	suffixes []string
	loaded   time.Time
}

var blockCacheV blockCache

const blockCacheTTL = 3 * time.Second

// blockedSuffixes returns all blocked suffixes: explicit blocklist entries
// plus domains from enabled categories.
func (db *DB) blockedSuffixes() []string {
	blockCacheV.mu.Lock()
	defer blockCacheV.mu.Unlock()
	if time.Since(blockCacheV.loaded) < blockCacheTTL && blockCacheV.suffixes != nil {
		return blockCacheV.suffixes
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
	blockCacheV.suffixes = out
	blockCacheV.loaded = time.Now()
	return out
}

// invalidateBlockCache forces a reload on the next IsBlocked call (used
// after blocklist/category changes).
func invalidateBlockCache() {
	blockCacheV.mu.Lock()
	blockCacheV.loaded = time.Time{}
	blockCacheV.mu.Unlock()
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
	db.Exec(`INSERT INTO blocked_categories(category,enabled) VALUES(?,?) ON CONFLICT(category) DO UPDATE SET enabled=excluded.enabled`, category, v)
	invalidateBlockCache()
	return true
}

// Setting reads a settings key ("" when unset).
func (db *DB) Setting(key string) string {
	var v string
	db.QueryRow(`SELECT COALESCE(value,'') FROM settings WHERE key=?`, key).Scan(&v)
	return v
}

// SetSetting writes a settings key.
func (db *DB) SetSetting(key, value string) {
	db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
}

// killCache caches the kill switch (checked per connection and per stream).
var (
	killMu     sync.Mutex
	killOn     bool
	killLoaded time.Time
)

// KillSwitch reports whether all tunnel traffic is suspended.
func (db *DB) KillSwitch() bool {
	killMu.Lock()
	defer killMu.Unlock()
	if time.Since(killLoaded) < time.Second {
		return killOn
	}
	killOn = db.Setting("kill_switch") == "1"
	killLoaded = time.Now()
	return killOn
}

// SetKillSwitch toggles the global kill switch.
func (db *DB) SetKillSwitch(on bool) {
	v := "0"
	if on {
		v = "1"
	}
	db.SetSetting("kill_switch", v)
	killMu.Lock()
	killOn = on
	killLoaded = time.Now()
	killMu.Unlock()
}

// PeerLimits returns the configured per-device caps (0 = unlimited).
func (db *DB) PeerLimits(token string) (maxBps, quotaBytes int64) {
	db.QueryRow(`SELECT COALESCE(max_bps,0), COALESCE(quota_bytes,0) FROM peers WHERE token=?`, token).Scan(&maxBps, &quotaBytes)
	return
}

// SetPeerLimits stores per-device caps and schedule.
func (db *DB) SetPeerLimits(token, schedule string, maxBps, quotaBytes int64) {
	db.Exec(`UPDATE peers SET schedule=?, max_bps=?, quota_bytes=? WHERE token=?`, schedule, maxBps, quotaBytes, token)
}

// SetPeerIP records the last seen source IP for a device (GeoIP in panel).
func (db *DB) SetPeerIP(token, ip string) {
	db.Exec(`UPDATE peers SET last_ip=? WHERE token=?`, ip, token)
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
