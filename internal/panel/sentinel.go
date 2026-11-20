package panel

// sentinel.go — panel-side proactive detection (v1.1.0).
//
// The relay-side sentinel (internal/server/sentinel.go) watches session
// events; this file watches *history*: where devices connected from, how
// fast new devices registered, and the automated response ladder's
// database half (AutoKick). otu-panel calls SentinelTick once a minute.
//
// Detection philosophy is the same as the relay side: generous thresholds,
// everything throttled per subject (persistently — restarts must not
// re-fire), and every action self-expiring. The operator's allowlisted
// devices are never auto-kicked: a false positive there would lock out the
// person holding the kill-switch allowlist.

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// AutoKick (L2): a temporary automated kick for one device. Only an
// approved peer is touched, never an allowlisted operator device, and the
// kick expires on its own via the reaper (db.go reaper releases expired
// kicks). Returns true when the peer was actually kicked.
func (db *DB) AutoKick(token, reason string, until time.Time) bool {
	if db == nil || !validTokenCharset(token) || len(reason) > 500 || !until.After(time.Now()) || until.After(time.Now().Add(24*time.Hour)) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	p, err := accessPolicy(ctx, tx, token)
	if err != nil || p.KillAllowed || p.Status != "approved" {
		return false
	}
	res, err := tx.ExecContext(ctx, `UPDATE peers SET status='kicked',kick_reason=?,kick_expires=? WHERE token=? AND status='approved' AND auth_epoch=?`, reason, until.UTC().Format("2006-01-02 15:04:05"), token, p.Generation)
	if err != nil {
		return false
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return false
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(kind,detail) VALUES('sentinel',?)`, "auto-kick "+shortPK(token)+": "+reason); err != nil {
		return false
	}
	return tx.Commit() == nil
}

// TravelHit is one impossible-travel finding: a token seen from two
// different countries inside the detection window.
type TravelHit struct {
	Token  string
	Device string
	A      string // first country, e.g. "Germany (203.0.113.9)"
	B      string // newest country
}

// DetectTravel scans the peer_ips history: two distinct countries for one
// device inside window. countryOf maps an IP to a country name ("" = skip;
// the caller passes the GeoIP lookup, which is nil-safe).
func (db *DB) DetectTravel(window time.Duration, countryOf func(string) string) []TravelHit {
	if db == nil || countryOf == nil || window <= 0 {
		return nil
	}
	rows, err := db.Query(`SELECT h.token, COALESCE(p.device_name,''), h.ip
		FROM peer_ips h LEFT JOIN peers p ON p.token=h.token
		WHERE h.at >= datetime('now', ?) ORDER BY h.at ASC`,
		fmt.Sprintf("-%d seconds", int(window.Seconds())))
	if err != nil {
		return nil
	}
	defer rows.Close()

	type loc struct{ country, ip string }
	type state struct {
		device string
		locs   []loc // ordered runs of distinct countries
	}
	per := map[string]*state{}
	for rows.Next() {
		var tok, dev, ip string
		if rows.Scan(&tok, &dev, &ip) != nil {
			continue
		}
		if ip == "" || ipLoopback(ip) {
			continue
		}
		c := strings.TrimSpace(countryOf(ip))
		if c == "" {
			continue
		}
		st := per[tok]
		if st == nil {
			st = &state{device: dev}
			per[tok] = st
		}
		if n := len(st.locs); n > 0 && st.locs[n-1].country == c {
			st.locs[n-1].ip = ip // same country, freshest address
			continue
		}
		st.locs = append(st.locs, loc{country: c, ip: ip})
	}

	var out []TravelHit
	for tok, st := range per {
		if len(st.locs) < 2 {
			continue
		}
		a, b := st.locs[len(st.locs)-2], st.locs[len(st.locs)-1]
		out = append(out, TravelHit{
			Token: tok, Device: st.device,
			A: a.country + " (" + a.ip + ")",
			B: b.country + " (" + b.ip + ")",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// SpreadHit is one device seen from many distinct source addresses.
type SpreadHit struct {
	Token  string
	Device string
	N      int
}

// DetectSpread counts distinct non-loopback source IPs per device in the
// window; >= minIPs is a hit (shared/lost token, or unusually mobile
// hardware). Alert-only by design — NAT handoffs can look like this.
func (db *DB) DetectSpread(minIPs int, window time.Duration) []SpreadHit {
	if db == nil || minIPs <= 0 || window <= 0 {
		return nil
	}
	rows, err := db.Query(`SELECT h.token, COALESCE(p.device_name,''), COUNT(DISTINCT h.ip) n
		FROM peer_ips h LEFT JOIN peers p ON p.token=h.token
		WHERE h.at >= datetime('now', ?) AND h.ip NOT IN ('127.0.0.1','::1')
		GROUP BY h.token HAVING n >= ? ORDER BY n DESC`,
		fmt.Sprintf("-%d seconds", int(window.Seconds())), minIPs)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []SpreadHit
	for rows.Next() {
		var h SpreadHit
		if rows.Scan(&h.Token, &h.Device, &h.N) == nil {
			out = append(out, h)
		}
	}
	return out
}

// RegBurstHit is a burst of fresh registrations from one subnet.
type RegBurstHit struct {
	Subnet string // "203.0.113.0/24" or the /64 for IPv6
	N      int
}

// DetectRegBurst counts peers created in the window, grouped by source
// subnet (/24 for IPv4, /64 for IPv6; the registration IP lands in
// last_ip via the register handler).
func (db *DB) DetectRegBurst(minN int, window time.Duration) []RegBurstHit {
	if db == nil || minN <= 0 || window <= 0 {
		return nil
	}
	rows, err := db.Query(`SELECT COALESCE(last_ip,''), COUNT(*) FROM peers
		WHERE created_at >= datetime('now', ?) GROUP BY last_ip`,
		fmt.Sprintf("-%d seconds", int(window.Seconds())))
	if err != nil {
		return nil
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var ip string
		var n int
		if rows.Scan(&ip, &n) != nil {
			continue
		}
		if sn := subnetKey(ip); sn != "" {
			counts[sn] += n
		}
	}
	var out []RegBurstHit
	for sn, n := range counts {
		if n >= minN {
			out = append(out, RegBurstHit{Subnet: sn, N: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N })
	return out
}

// SentinelTick runs the panel-side detectors once. otu-panel calls it on a
// one-minute cadence. countryOf may be nil (travel detection degrades).
func (db *DB) SentinelTick(countryOf func(string) string) {
	if db == nil {
		return
	}
	mode := strings.TrimSpace(db.Setting("sentinel_mode"))
	if mode == "" {
		mode = "respond"
	}
	if mode == "off" {
		return
	}

	for _, h := range db.DetectTravel(30*time.Minute, countryOf) {
		if !db.throttleKV("travel|"+h.Token, 30*time.Minute) {
			continue
		}
		// Country changes are not a distance/speed estimate: VPN egress,
		// mobile handoffs and GeoIP errors can cause legitimate transitions.
		msg := "source-country change for device " + shortPK(h.Token) + ": " + h.A + " → " + h.B + " within 30m — review required, not proof of impossible travel"
		db.RecordAlert("warning", "sentinel", msg)
	}
	for _, h := range db.DetectSpread(10, 24*time.Hour) {
		if !db.throttleKV("spread|"+h.Token, 6*time.Hour) {
			continue
		}
		db.RecordAlert("warning", "sentinel", fmt.Sprintf(
			"device %s used %d distinct source IPs in 24h — shared token or unusual mobility?", shortPK(h.Token), h.N))
	}
	for _, h := range db.DetectRegBurst(5, time.Hour) {
		if !db.throttleKV("regburst|"+h.Subnet, 3*time.Hour) {
			continue
		}
		db.RecordAlert("warning", "sentinel", fmt.Sprintf(
			"registration burst: %d new devices from %s in 1h", h.N, h.Subnet))
	}
}

// throttleKV is a persistent per-subject throttle: true when key has not
// fired within d. State lives in the settings table so restarts and
// redeploys do not reset the gates.
func (db *DB) throttleKV(key string, d time.Duration) bool {
	if db == nil || len(key) < 1 || len(key) > 512 || d <= 0 || d > 24*time.Hour {
		return false
	}
	k := "sentinel_ts_" + key
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, k).Scan(&raw)
	if err != nil && err != sql.ErrNoRows {
		return false
	}
	var last int64
	if err == nil {
		if _, err := fmt.Sscanf(raw, "%d", &last); err != nil {
			return false
		}
	}
	now := time.Now().Unix()
	if last > 0 && now-last < int64(d.Seconds()) {
		return false
	}
	if last == 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key LIKE 'sentinel_ts_%' AND CAST(value AS INTEGER)<?`, now-24*3600); err != nil {
			return false
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM settings WHERE key LIKE 'sentinel_ts_%'`).Scan(&count); err != nil || count >= 8192 {
			return false
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, fmt.Sprintf("%d", now)); err != nil {
		return false
	}
	return tx.Commit() == nil
}

func shortPK(t string) string {
	if len(t) > 8 {
		return t[:8]
	}
	return t
}

func ipLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// subnetKey maps an IP to its grouping key: /24 for IPv4, /64 for IPv6
// ("" for unparseable input).
func subnetKey(ip string) string {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
