package server

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// sentinelStub is a full-capability panel reporter: alerts, events, kicks
// and a settings map.
type sentinelStub struct {
	mu     sync.Mutex
	alerts []string
	events []string
	kicks  []string
	cfg    map[string]string
}

func newSentinelStub() *sentinelStub { return &sentinelStub{cfg: map[string]string{}} }

func (s *sentinelStub) RecordAlert(sev, kind, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, sev+"|"+kind+"|"+msg)
}

func (s *sentinelStub) RecordAlertOnce(sev, kind, msg string) { s.RecordAlert(sev, kind, msg) }

func (s *sentinelStub) RecordEvent(kind, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, kind+"|"+detail)
}

func (s *sentinelStub) AutoKick(token, reason string, until time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kicks = append(s.kicks, token+"|"+reason)
	return true
}

func (s *sentinelStub) Setting(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg[key]
}

func (s *sentinelStub) alertText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.alerts, "\n")
}

func (s *sentinelStub) kickCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.kicks)
}

func (s *sentinelStub) eventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// TestSentinelAuthFloodBans: sustained failed handshakes raise exactly one
// alert and, in respond mode, a self-expiring guard ban.
func TestSentinelAuthFloodBans(t *testing.T) {
	st := newSentinelStub()
	g := NewGuard(4, 32, 30*time.Second, 10*time.Minute)
	s := NewSentinel(st, g)

	for i := 0; i < sentinelAuthFlood; i++ {
		s.AuthFail("203.0.113.9")
	}
	if got := st.alertText(); !strings.Contains(got, "auth-failure flood") || !strings.Contains(got, "203.0.113.9") {
		t.Fatalf("want auth-flood alert, got %q", got)
	}
	if st.eventCount() == 0 {
		t.Fatal("ban must be recorded as an event")
	}
	if rel := g.Acquire("203.0.113.9"); rel != nil {
		rel()
		t.Fatal("respond mode must have banned the flooding IP")
	}
	// Alerts are throttled: more failures must not storm the feed.
	for i := 0; i < 30; i++ {
		s.AuthFail("203.0.113.9")
	}
	if n := strings.Count(st.alertText(), "auth-failure flood"); n != 1 {
		t.Fatalf("want 1 throttled alert, got %d", n)
	}
}

// TestSentinelModes: off is fully silent, alert records but never acts,
// respond acts.
func TestSentinelModes(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		wantBan bool
		wantAny bool
	}{
		{"off", false, false},
		{"alert", false, true},
		{"respond", true, true},
	} {
		st := newSentinelStub()
		st.cfg["sentinel_mode"] = tc.mode
		g := NewGuard(4, 32, 30*time.Second, 10*time.Minute)
		s := NewSentinel(st, g)
		for i := 0; i < sentinelAuthFlood+2; i++ {
			s.AuthFail("198.51.100.7")
		}
		hasAlert := strings.Contains(st.alertText(), "auth-failure flood")
		if hasAlert != tc.wantAny {
			t.Errorf("mode %s: alert=%v, want %v", tc.mode, hasAlert, tc.wantAny)
		}
		banned := g.Acquire("198.51.100.7") == nil
		if banned != tc.wantBan {
			t.Errorf("mode %s: banned=%v, want %v", tc.mode, banned, tc.wantBan)
		}
	}
}

// A bad signature must not give a token thief a remote victim-kick primitive.
func TestSentinelStolenTokenCannotKickVictim(t *testing.T) {
	st := newSentinelStub()
	s := NewSentinel(st, nil)

	s.StolenToken("stolen-token-abcdef", "203.0.113.77", "handshake signature mismatch")
	if st.kickCount() != 0 {
		t.Fatalf("unverified evidence kicked the victim: %d", st.kickCount())
	}
	if got := st.alertText(); !strings.Contains(got, "critical|security|") || !strings.Contains(got, "possible stolen token") {
		t.Fatalf("want critical security alert, got %q", got)
	}
	// Repeat attempts are throttled: no kick storm, no alert storm.
	s.StolenToken("stolen-token-abcdef", "203.0.113.77", "handshake signature mismatch")
	if st.kickCount() != 0 {
		t.Fatalf("repeat unverified evidence kicked the victim: %d", st.kickCount())
	}
	if n := strings.Count(st.alertText(), "possible stolen token"); n != 1 {
		t.Fatalf("want 1 alert, got %d", n)
	}
}

// TestSentinelProbeFlood: probing floods alert; loopback probes (health
// checks, the ssh tier's ingress) never do.
func TestSentinelProbeFlood(t *testing.T) {
	st := newSentinelStub()
	s := NewSentinel(st, nil)

	for i := 0; i < sentinelProbeFlood; i++ {
		s.Probe("198.51.100.44", "plain")
	}
	if got := st.alertText(); !strings.Contains(got, "scanning from 198.51.100.44") {
		t.Fatalf("want scanning alert, got %q", got)
	}
	before := len(st.alerts)
	for i := 0; i < 50; i++ {
		s.Probe("127.0.0.1", "plain")
		s.Probe("::1", "plain")
	}
	if len(st.alerts) != before {
		t.Fatal("loopback probes must be ignored")
	}
}

// TestSentinelChurningAndAggregation: per-device reconnect storms and
// many-devices-behind-one-IP bursts both alert.
func TestSentinelChurningAndAggregation(t *testing.T) {
	st := newSentinelStub()
	s := NewSentinel(st, nil)

	for i := 0; i < sentinelChurnCount; i++ {
		s.SessionStart("churny-token-123456", "203.0.113.11")
	}
	if got := st.alertText(); !strings.Contains(got, "session churn") {
		t.Fatalf("want churn alert, got %q", got)
	}

	st2 := newSentinelStub()
	s2 := NewSentinel(st2, nil)
	for i := 0; i < sentinelIPAggCount; i++ {
		s2.SessionStart("agg-token-123456", "203.0.113.12")
	}
	if got := st2.alertText(); !strings.Contains(got, "session burst from 203.0.113.12") {
		t.Fatalf("want aggregation alert, got %q", got)
	}
}

// TestSentinelRollingWindow: counts expire out of the rolling window —
// seven failures now plus one ten minutes later must not fire.
func TestSentinelRollingWindow(t *testing.T) {
	st := newSentinelStub()
	s := NewSentinel(st, nil)
	cur := time.Now()
	s.now = func() time.Time { return cur }

	for i := 0; i < sentinelAuthFlood-1; i++ {
		s.AuthFail("203.0.113.99")
	}
	cur = cur.Add(sentinelAuthWindow + time.Minute)
	s.AuthFail("203.0.113.99")
	if got := st.alertText(); got != "" {
		t.Fatalf("stale events must not alert, got %q", got)
	}
}

// TestSentinelHostileNet: device-reported TLS interception alerts once per
// device per six hours, never per health report.
func TestSentinelHostileNet(t *testing.T) {
	st := newSentinelStub()
	s := NewSentinel(st, nil)

	s.HostileNet("hostile-device-token")
	s.HostileNet("hostile-device-token")
	s.HostileNet("hostile-device-token")
	if n := strings.Count(st.alertText(), "TLS interception"); n != 1 {
		t.Fatalf("want 1 throttled hostile alert, got %d", n)
	}
	if !strings.Contains(st.alertText(), "hostile-device-token"[:8]) {
		t.Fatalf("alert must name the device prefix: %q", st.alertText())
	}
}

// TestEnsureSentinelMemoizesAndWires: EnsureSentinel returns one shared
// instance per Options and binds the panel DB as reporter (Handler() and
// main.go's error-log writer rely on both properties).
func TestEnsureSentinelMemoizesAndWires(t *testing.T) {
	st := newSentinelStub()
	opt := Options{Token: "master-token-123456789", PanelDB: stubPanel{st}}
	s1 := opt.EnsureSentinel()
	if s2 := opt.EnsureSentinel(); s1 != s2 {
		t.Fatal("EnsureSentinel must memoize")
	}
	for i := 0; i < sentinelAuthFlood+2; i++ {
		s1.AuthFail("203.0.113.31")
	}
	if !strings.Contains(st.alertText(), "auth-failure flood") {
		t.Fatalf("wired reporter received no alert: %q", st.alertText())
	}
}

// stubPanel adapts sentinelStub to the full PanelDB interface for the
// Handler wiring test (everything inert except alerts).
type stubPanel struct{ st *sentinelStub }

func (p stubPanel) CheckToken(string) (string, string, string, error) { return "approved", "", "", nil }
func (p stubPanel) RecordTraffic(string, int64, int64)                {}
func (p stubPanel) IsBlocked(string) bool                             { return false }
func (p stubPanel) BlockWhy(string) string                            { return "" }
func (p stubPanel) KillSwitch() bool                                  { return false }
func (p stubPanel) KillSwitchReason() string                          { return "" }
func (p stubPanel) KillSwitchAllow(string) bool                       { return false }
func (p stubPanel) PeerLimits(string) (int64, int64)                  { return 0, 0 }
func (p stubPanel) SSHTierLimits() (int64, int64, int64)              { return 0, 0, 0 }
func (p stubPanel) SetPeerIP(string, string)                          {}
func (p stubPanel) RecordHealth(string, string, string, string, float64, float64, float64, int64, float64, float64, float64) {
}
func (p stubPanel) BanReason(string) string           { return "" }
func (p stubPanel) TouchPeer(string)                  {}
func (p stubPanel) KnownPeer(string) bool             { return true }
func (p stubPanel) RecordVisit(string, string)        {}
func (p stubPanel) SSHPubKey(string) string           { return "" }
func (p stubPanel) RecordAlert(sev, kind, msg string) { p.st.RecordAlert(sev, kind, msg) }
func (p stubPanel) MarkV5(string)                     {}
func (p stubPanel) V5Seen(string) bool                { return false }
