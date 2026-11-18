package panel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"opentunnel/internal/authority"
	"opentunnel/internal/protocol"
)

func TestPrivacyDefaultPreservesMonitoringAndOptInKeepsEnforcement(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	p, err := db.PrivacyPolicy()
	if err != nil || p.Mode != "preserve" || p.VisitDays != 0 || p.HealthDays != 0 || p.IPDays != 7 {
		t.Fatal("existing fleet privacy defaults changed", err)
	}
	db.RecordVisit(token, "fixture.example")
	db.SetPeerIP(token, "192.0.2.5")
	db.RecordHealth(token, "fixture", "windows", "amd64", 50, 50, 40, 10, 20, 3, 0)
	before, err := db.AccessPolicy(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetPrivacyPolicy(t.Context(), PrivacyPolicy{Mode: "minimal", IPDays: 1, VisitDays: 1, HealthDays: 1}, false); err != nil {
		t.Fatal(err)
	}
	db.RecordVisit(token, "other.example")
	db.SetPeerIP(token, "192.0.2.6")
	db.RecordHealth(token, "fixture2", "windows", "amd64", 99, 99, 90, 999, 999, 3, 0)
	var visits, ips int
	if err := db.QueryRow(`SELECT COUNT(*) FROM visits`).Scan(&visits); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM peer_ips`).Scan(&ips); err != nil {
		t.Fatal(err)
	}
	if visits != 1 || ips != 1 {
		t.Fatal("minimal mode still stored new domains/IP history", visits, ips)
	}
	var version string
	var cpu, mem, temp, uptime int
	if err := db.QueryRow(`SELECT version,cpu_pct,mem_pct,temp_c,uptime_s FROM device_health WHERE token=?`, token).Scan(&version, &cpu, &mem, &temp, &uptime); err != nil {
		t.Fatal(err)
	}
	if version != "fixture2" || cpu != 0 || mem != 0 || temp != 0 || uptime != 0 {
		t.Fatal("minimal mode lost version or stored hardware posture")
	}
	after, err := db.AccessPolicy(token)
	if err != nil || after.Generation != before.Generation || after.Status != before.Status || after.QuotaBytes != before.QuotaBytes {
		t.Fatal("privacy change rewrote enforcement", err)
	}
	if err := db.PeerStateAction(token, "ban", "fixture", ""); err != nil {
		t.Fatal(err)
	}
	after, err = db.AccessPolicy(token)
	if err != nil || after.Status != "banned" {
		t.Fatal("privacy mode lifted a ban", err)
	}
}

func TestLegacyControlHealthCannotWriteAfterChannelUpgrade(t *testing.T) {
	db := newTestDB(t)
	token, generation, pub := centralPeer(t, db)
	request := authority.ControlRequest{Token: token, Generation: generation, PublicKey: pub, Request: protocol.CtrlRequest{Op: "health", Version: "legacy-session"}}
	if _, err := db.ControlSession(t.Context(), request, false); err == nil {
		t.Fatal("already connected legacy session ignored sticky channel upgrade")
	}
	if _, err := db.ControlSession(t.Context(), request, true); err != nil {
		t.Fatal("verified channel session refused", err)
	}
}

func TestPrivacyRetentionOnlyPurgesExpiredTelemetryAndIsAudited(t *testing.T) {
	db := newTestDB(t)
	token := accessPeer(t, db)
	if _, err := db.Exec(`INSERT INTO visits(token,domain,hits,last_seen) VALUES(?,'fixture.example',1,datetime('now','-10 days'))`, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO device_health(token,version,at) VALUES(?,'fixture',datetime('now','-10 days'))`, token); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPrivacyPolicy(t.Context(), PrivacyPolicy{Mode: "minimal", VisitDays: 1, HealthDays: 1, IPDays: 1}, true); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT (SELECT COUNT(*) FROM visits)+(SELECT COUNT(*) FROM device_health)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired telemetry not pruned", err)
	}
	if !db.KnownPeer(token) {
		t.Fatal("retention deleted identity")
	}
	if _, err := db.Exec(`CREATE TRIGGER deny_privacy_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPrivacyPolicy(t.Context(), PrivacyPolicy{Mode: "preserve", IPDays: 7}, true); err == nil {
		t.Fatal("privacy audit fault reported success")
	}
	p, _ := db.PrivacyPolicy()
	if p.Mode != "minimal" {
		t.Fatal("privacy policy partially changed on audit fault")
	}
}

func TestPrivacyMalformedOrUnconfirmedPurgeChangesNothing(t *testing.T) {
	db := newTestDB(t)
	h := New(db, NewAuth(db), false)
	for _, body := range []string{`null`, `{} {}`, `{"policy":{"mode":"minimal","peer_ip_retention_days":1},"apply_retention_now":true,"confirm_retention_purge":false}`, `{"policy":{"mode":"minimal","mode":"preserve","peer_ip_retention_days":1}}`} {
		w := httptest.NewRecorder()
		h.privacyAPI(w, httptest.NewRequest(http.MethodPost, "/admin/api/privacy", strings.NewReader(body)))
		p, _ := db.PrivacyPolicy()
		if w.Code < 400 || p.Mode != "preserve" {
			t.Fatal("invalid privacy input changed policy", w.Code)
		}
	}
}

func TestBoundTelemetryCannotRaceRekeyOrRevocation(t *testing.T) {
	db := newTestDB(t)
	token, generation, pub := centralPeer(t, db)
	req := authority.ControlRequest{Token: token, Generation: generation, PublicKey: pub, Request: protocol.CtrlRequest{Op: "health", Version: "fixture", CPUPct: 10}}
	if _, err := db.ControlBound(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RekeyPeer(token, pub, testKeyLine(t)); err != nil {
		t.Fatal(err)
	}
	req.Request.Version = "stale"
	if _, err := db.ControlBound(t.Context(), req); err == nil {
		t.Fatal("stale session wrote telemetry to replacement identity")
	}
	var version string
	if err := db.QueryRow(`SELECT version FROM device_health WHERE token=?`, token).Scan(&version); err != nil || version != "fixture" {
		t.Fatal("stale telemetry partly committed", err)
	}
}
