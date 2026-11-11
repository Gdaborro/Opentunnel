package server

// sentinel.go — proactive threat detection (L1) and the automated response
// ladder (L2), v1.1.0.
//
// The guard (guard.go) already *contains* abuse: per-IP caps, punitive bans
// after failed handshakes, per-identity session caps — all invisible, all
// memory-only, none of it reported. The sentinel is the missing nervous
// system: it watches the same events, detects sustained or high-signal
// patterns, raises panel alerts (so the operator sees attacks in days, not
// months), and — in "respond" mode — applies bounded, self-expiring
// countermeasures:
//
//   - auth-failure flood from one IP  → 30-minute guard ban + alert
//   - unverified token use (v5 signature mismatch / v4 downgrade) → critical
//     alert; sustained failures may ban the source, never the named victim
//   - scanning/probing floods → alert only (probers already get the decoy;
//     changing their response would itself fingerprint the relay)
//
// Everything is deliberately conservative: thresholds are high, every alert
// and action is throttled (never a storm), every action expires on its own,
// and allowlisted operator devices are never auto-kicked. Detection keeps
// running while the kill switch is engaged — that is exactly when probing
// peaks.

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Sentinel thresholds. Deliberately generous: one alert should mean
// something, and a false response costs more than a missed alert. All
// windows are rolling.
const (
	sentinelAuthWindow  = 10 * time.Minute
	sentinelAuthFlood   = 8 // failed handshakes per IP
	sentinelProbeWindow = 10 * time.Minute
	sentinelProbeFlood  = 20 // probes per IP (plain hits / junk TLS)
	sentinelGuardWindow = 10 * time.Minute
	sentinelGuardDenied = 10 // guard-denied arrivals per IP
	sentinelChurnWindow = 5 * time.Minute
	sentinelChurnCount  = 12 // sessions per device
	sentinelIPAggCount  = 30 // sessions per source IP across devices

	sentinelThrottle = 30 * time.Minute // min gap between same-key alerts
	sentinelBanTime  = 30 * time.Minute // auth-flood IP ban
)

// Reporter is the panel surface the sentinel reports through. The relay's
// PanelDB interface satisfies it (RecordAlert is part of PanelDB). Optional
// richer capabilities are discovered by type assertion: RecordAlertOnce,
// RecordEvent and Setting (see *panel.DB). A nil reporter (tests,
// legacy static-token mode) degrades to journal logging only.
type Reporter interface {
	RecordAlert(severity, kind, message string)
}

type alertOncer interface {
	RecordAlertOnce(severity, kind, message string)
}

type eventRecorder interface {
	RecordEvent(kind, detail string)
}

type settingsReader interface {
	Setting(key string) string
}

// Sentinel watches session-level events. Safe for concurrent use.
type Sentinel struct {
	rep Reporter
	g   *Guard

	mu      sync.Mutex
	buckets map[string][]int64   // class\x00subject -> event unixnano timestamps
	seen    map[string]time.Time // throttle key -> last alert/action
	mode    string
	modeAt  time.Time
	now     func() time.Time
}

// NewSentinel builds a detector reporting through rep (may be nil) and
// banning through g (may be nil).
func NewSentinel(rep Reporter, g *Guard) *Sentinel {
	return &Sentinel{
		rep:     rep,
		g:       g,
		buckets: map[string][]int64{},
		seen:    map[string]time.Time{},
		now:     time.Now,
	}
}

// EnsureSentinel lazily creates the Options' sentinel, wiring the panel DB
// (when present) as the reporter and the session guard as the enforcer.
// main.go calls this once so the HTTP error log and the relay share one
// instance; Handler() calls it for direct-construction callers.
func (o *Options) EnsureSentinel() *Sentinel {
	if o.Sntl != nil {
		return o.Sntl
	}
	var rep Reporter
	if o.PanelDB != nil {
		rep = o.PanelDB
	}
	o.Sntl = NewSentinel(rep, o.guard())
	return o.Sntl
}

// sentinel returns the Options' sentinel, creating it on the fly when the
// caller bypassed Handler() (rare: direct handleSession callers).
func (o *Options) sentinel() *Sentinel {
	if o.Sntl != nil {
		return o.Sntl
	}
	var rep Reporter
	if o.PanelDB != nil {
		rep = o.PanelDB
	}
	return NewSentinel(rep, o.guard())
}

// GuardInstance exposes the relay's session guard (sentinel L2 wiring in
// main.go; the guard is otherwise package-private).
func (o *Options) GuardInstance() *Guard { return o.guard() }

// Mode reports the operator-selected response level:
//
//	"off"     — detections disabled entirely
//	"alert"   — detect and alert, never act
//	"respond" — detect, alert, and apply bounded countermeasures (default)
//
// Cached for 15 s; the settings table is read at most once per window.
func (s *Sentinel) Mode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode != "" && s.now().Sub(s.modeAt) < 15*time.Second {
		return s.mode
	}
	m := "respond"
	if r, ok := s.rep.(settingsReader); ok {
		switch v := strings.TrimSpace(r.Setting("sentinel_mode")); v {
		case "off", "alert", "respond":
			m = v
		}
	}
	s.mode, s.modeAt = m, s.now()
	return m
}

func (s *Sentinel) active() bool  { return s.Mode() != "off" }
func (s *Sentinel) respond() bool { return s.Mode() == "respond" }

// hit records one event and returns the count inside the rolling window.
func (s *Sentinel) hit(class, subject string, window time.Duration) int {
	now := s.now().UnixNano()
	cut := now - int64(window)
	key := class + "\x00" + subject

	s.mu.Lock()
	defer s.mu.Unlock()
	ev := s.buckets[key]
	for len(ev) > 0 && ev[0] < cut {
		ev = ev[1:]
	}
	ev = append(ev, now)
	s.buckets[key] = ev
	if len(s.buckets) > 4096 {
		s.gcLocked(now)
	}
	return len(ev)
}

// gcLocked drops buckets whose newest event is older than an hour.
func (s *Sentinel) gcLocked(now int64) {
	cut := now - int64(time.Hour)
	for k, ev := range s.buckets {
		if len(ev) == 0 || ev[len(ev)-1] < cut {
			delete(s.buckets, k)
		}
	}
	for k, t := range s.seen {
		if now-t.UnixNano() > int64(2*time.Hour) {
			delete(s.seen, k)
		}
	}
}

// throttle returns true when key has not fired within d (and marks it).
func (s *Sentinel) throttle(key string, d time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.seen[key]; ok && now.Sub(last) < d {
		return false
	}
	s.seen[key] = now
	if len(s.seen) > 8192 {
		s.gcLocked(now.UnixNano())
	}
	return true
}

// alert emits a throttled alert (panel + journal). The throttle is
// per-key so distinct subjects never mask each other, and stale keys
// cannot re-alert more than once per window.
func (s *Sentinel) alert(key, severity, kind, message string) {
	s.alertD(key, severity, kind, message, sentinelThrottle)
}

// alertD is alert with an explicit throttle window.
func (s *Sentinel) alertD(key, severity, kind, message string, d time.Duration) {
	if !s.throttle("alert|"+key, d) {
		return
	}
	if s.rep != nil {
		if w, ok := s.rep.(alertOncer); ok {
			w.RecordAlertOnce(severity, kind, message)
		} else {
			s.rep.RecordAlert(severity, kind, message)
		}
	}
	log.Printf("sentinel: %s %s: %s", severity, kind, message)
}

// event records an action in the panel event feed (best effort).
func (s *Sentinel) event(detail string) {
	if e, ok := s.rep.(eventRecorder); ok {
		e.RecordEvent("sentinel", detail)
	}
}

// AuthFail: a malformed handshake or a bad token from ip. Brute force and
// token scanning land here; sustained pressure escalates to a 30-minute
// guard ban (respond mode) — the peer just keeps seeing the decoy.
func (s *Sentinel) AuthFail(ip string) {
	if ip == "" || isLoopbackIP(ip) || !s.active() {
		return
	}
	n := s.hit("auth", ip, sentinelAuthWindow)
	if n < sentinelAuthFlood {
		return
	}
	took := false
	if n == sentinelAuthFlood && s.respond() && s.g != nil && s.throttle("act|auth|"+ip, sentinelThrottle) {
		s.g.BanIP(ip, sentinelBanTime)
		took = true
		s.event("banned " + ip + " for " + sentinelBanTime.String() + " (auth-failure flood)")
	}
	msg := fmt.Sprintf("auth-failure flood from %s: %d failed handshakes in %s", ip, n, sentinelAuthWindow)
	if took {
		msg += " — IP banned for " + sentinelBanTime.String()
	}
	s.alert("auth|"+ip, "warning", "sentinel", msg)
}

// StolenToken observes an attempt that knows a token but has not proven
// private-key possession. Automatically kicking the named device here lets
// a token thief disconnect the legitimate victim by sending one bad signature.
// Alert on the evidence; only the failing source may be rate-limited.
func (s *Sentinel) StolenToken(token, ip, what string) {
	if token == "" || !s.active() {
		return
	}
	s.hit("stolen", token, sentinelThrottle)
	s.AuthFail(ip)
	msg := what + " for device " + shortToken(token) + " — possible stolen token"
	if ip != "" && !isLoopbackIP(ip) {
		msg += " (source " + ip + "; device left connected)"
	}
	s.alert("stolen|"+token, "critical", "security", msg)
}

// Probe: an active-probing signal from ip — a non-upgrade request on the
// tunnel path, or a junk TLS handshake (class labels the error kind).
// Alert only: probers already receive the decoy, and changing that response
// (ban/timeout/reset) would itself distinguish the relay.
func (s *Sentinel) Probe(ip, class string) {
	if ip == "" || isLoopbackIP(ip) || !s.active() {
		return
	}
	n := s.hit("probe", ip, sentinelProbeWindow)
	if n < sentinelProbeFlood {
		return
	}
	s.alert("probe|"+ip, "warning", "sentinel",
		fmt.Sprintf("scanning from %s: %d probes in %s (latest: %s)", ip, n, sentinelProbeWindow, class))
}

// GuardDenied: an arrival was over the per-IP cap or already banned.
// Sustained pressure is worth an alert (distributed abuse, or a CGNAT
// sharing one cap — the operator can decide).
func (s *Sentinel) GuardDenied(ip string) {
	if ip == "" || !s.active() {
		return
	}
	n := s.hit("denied", ip, sentinelGuardWindow)
	if n < sentinelGuardDenied {
		return
	}
	s.alert("denied|"+ip, "warning", "sentinel",
		fmt.Sprintf("rate-limit pressure from %s: %d denied arrivals in %s (cap or ban active)", ip, n, sentinelGuardWindow))
}

// HostileNet: a device reports that its local network intercepts TLS (its
// adaptive stealth latched hostile mode) — a censor or enterprise
// middlebox is actively MITM'ing that device. Health reports arrive every
// few minutes while the condition persists, so the alert is throttled to
// one per device per six hours: visible, never a storm.
func (s *Sentinel) HostileNet(token string) {
	if token == "" || !s.active() {
		return
	}
	s.hit("hostile", token, 24*time.Hour)
	s.alertD("hostile|"+token, "warning", "sentinel",
		"device "+shortToken(token)+" reports TLS interception on its current network (hostile middlebox)", 6*time.Hour)
}

// SessionStart: one authenticated session began. Watches per-device churn
// (flapping links read as reconnect storms) and per-IP aggregation (many
// devices behind one address — NAT is normal, bursts beyond the cap count
// are not).
func (s *Sentinel) SessionStart(token, ip string) {
	if !s.active() {
		return
	}
	if token != "" {
		if n := s.hit("churn", token, sentinelChurnWindow); n >= sentinelChurnCount {
			s.alert("churn|"+token, "warning", "sentinel",
				fmt.Sprintf("session churn for device %s: %d sessions in %s", shortToken(token), n, sentinelChurnWindow))
		}
	}
	if ip != "" && !isLoopbackIP(ip) {
		if n := s.hit("ipagg", ip, sentinelChurnWindow); n >= sentinelIPAggCount {
			s.alert("ipagg|"+ip, "warning", "sentinel",
				fmt.Sprintf("session burst from %s: %d sessions in %s", ip, n, sentinelChurnWindow))
		}
	}
}
