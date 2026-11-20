package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"opentunnel/internal/serverpool"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelLatchSurvivesRestartRekeyAndLegacyCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channel.db")
	db, err := Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	token := accessPeer(t, db)
	key := testKeyLine(t)
	if _, err := db.Exec(`UPDATE peers SET ssh_pubkey=? WHERE token=?`, key, token); err != nil {
		t.Fatal(err)
	}
	if err := db.CommitAuthentication(token, "epoch-a", key, true); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path, 14)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.AccessPolicy(token)
	if err != nil || !p.ChannelSeen || !p.V5Seen {
		t.Fatal("upgrade not sticky after restart", err)
	}
	if err := db.CommitV5(token, "epoch-a", key); err == nil {
		t.Fatal("v5 downgrade accepted after channel upgrade")
	}
	replacement := testKeyLine(t)
	if _, err := db.RekeyPeer(token, key, replacement); err != nil {
		t.Fatal(err)
	}
	if err := db.PeerStateAction(token, "approve", "", ""); err != nil {
		t.Fatal(err)
	}
	p, err = db.AccessPolicy(token)
	if err != nil || !p.ChannelSeen || p.Generation == "epoch-a" {
		t.Fatal("rekey reset the authentication requirement", err)
	}
	if p.ChannelVerified {
		t.Fatal("newly rekeyed identity inherited verification evidence from the old key")
	}
	if err := db.CommitAuthentication(token, "epoch-a", key, true); err == nil {
		t.Fatal("stale session latched replacement identity")
	}
	if err := db.CommitV5(token, p.Generation, replacement); err == nil {
		t.Fatal("rekey reopened legacy authentication")
	}
	if err := db.CommitAuthentication(token, p.Generation, replacement, true); err != nil {
		t.Fatal("rekeyed channel identity could not verify", err)
	}
	p, err = db.AccessPolicy(token)
	if err != nil || !p.ChannelVerified {
		t.Fatal("current generation was not recorded", err)
	}
}

func TestCanaryCapabilityPreservesExactLegacySchema(t *testing.T) {
	db := newTestDB(t)
	h, err := New(db, NewAuth(db), false).WithServerPool(syntheticEnrollmentPool, false)
	if err != nil {
		t.Fatal(err)
	}
	h.WithPoolChannelSupport(true)
	legacy := httptest.NewRecorder()
	h.serverInfo(legacy, httptest.NewRequest(http.MethodGet, serverpool.InfoPath, nil))
	if strings.Contains(legacy.Body.String(), "channel_auth") {
		t.Fatal("canary support changed legacy capability schema")
	}
	var old struct {
		Version   int    `json:"version"`
		Pool      string `json:"pool_id"`
		Authority string `json:"authority_id"`
		Login     bool   `json:"login_required"`
		Approval  bool   `json:"approval_required"`
	}
	if serverpool.DecodeStrict(legacy.Body.Bytes(), &old) != nil || old.Version != 1 {
		t.Fatal("old strict client cannot read migration capability")
	}
	req := httptest.NewRequest(http.MethodGet, serverpool.InfoPath, nil)
	req.Header.Set("X-Otu-Profile-Version", "2")
	newResponse := httptest.NewRecorder()
	h.serverInfo(newResponse, req)
	var info serverpool.Info
	if json.Unmarshal(newResponse.Body.Bytes(), &info) != nil || info.Version != 2 || !info.ChannelAuthSupported || info.RequireChannelAuth {
		t.Fatal("channel canary support not advertised without automatic enforcement")
	}
}

func TestPoolChannelPolicyCannotChangeByRestart(t *testing.T) {
	db := newTestDB(t)
	info, err := db.BindServerPoolAuthentication(syntheticEnrollmentPool, true, true)
	if err != nil || !info.RequireChannelAuth || info.Version != 2 {
		t.Fatal("channel policy not bound", err)
	}
	if _, err := db.BindServerPool(syntheticEnrollmentPool, true); err == nil {
		t.Fatal("legacy process silently removed bound channel policy")
	}
	if _, err := db.BindServerPoolAuthentication(syntheticEnrollmentPool, false, true); err == nil {
		t.Fatal("login requirement silently changed")
	}
}
