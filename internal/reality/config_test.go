package reality

import (
	"encoding/json"
	"strings"
	"testing"
)

func testProfile(t *testing.T) Profile {
	t.Helper()
	_, password, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id, err := GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	short, err := GenerateShortID()
	if err != nil {
		t.Fatal(err)
	}
	return Profile{Version: 1, Endpoint: "127.0.0.1:19443", ServerName: "cover.test", UUID: id, Password: password, ShortID: short, Target: "127.0.0.1:18082"}
}

func TestClientConfigurationIsAuthenticatedAndFixedTarget(t *testing.T) {
	p := testProfile(t)
	data, err := ClientJSON(p, "127.0.0.1:19090", "otu", strings.Repeat("x", 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateClientJSON(data, "127.0.0.1:19090", p.Target); err != nil {
		t.Fatal(err)
	}
	var d document
	_ = json.Unmarshal(data, &d)
	d.Routing.Rules = d.Routing.Rules[:1]
	modified, _ := json.Marshal(d)
	if err := ValidateClientJSON(modified, "127.0.0.1:19090", p.Target); err == nil {
		t.Fatal("client admitted missing final deny")
	}
	d.Routing.Rules = fixedRules("otu-local", p.Target, "reality")
	d.Outbounds[0].Protocol = "freedom"
	modified, _ = json.Marshal(d)
	if err := ValidateClientJSON(modified, "127.0.0.1:19090", p.Target); err == nil {
		t.Fatal("client admitted general direct egress")
	}
}

func TestServerConfinementRejectsMissingRedirectOrFinalRules(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p := testProfile(t)
	data, err := ServerJSON(ServerParams{Listen: "127.0.0.1:19443", Target: p.Target, CoverTarget: "127.0.0.1:18443", ServerName: p.ServerName, PrivateKey: priv, UUIDs: []string{p.UUID}, ShortIDs: []string{p.ShortID}, AllowLoopbackCover: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateServerJSON(data, "127.0.0.1:19443", p.Target); err != nil {
		t.Fatal(err)
	}
	var d document
	_ = json.Unmarshal(data, &d)
	d.Outbounds[1].Settings = raw(freedomSettings{Redirect: "127.0.0.1:18083"})
	modified, _ := json.Marshal(d)
	if err := ValidateServerJSON(modified, "127.0.0.1:19443", p.Target); err == nil {
		t.Fatal("server admitted a different final target")
	}
}

func TestREALITYRejectsCoverMismatchAndWildcard(t *testing.T) {
	p := testProfile(t)
	priv, _, _ := GenerateKey()
	for _, cover := range []string{"other.test:443", "127.0.0.1:443", "*:443"} {
		if _, err := ServerJSON(ServerParams{Listen: "0.0.0.0:19443", Target: p.Target, CoverTarget: cover, ServerName: p.ServerName, PrivateKey: priv, UUIDs: []string{p.UUID}, ShortIDs: []string{p.ShortID}}); err == nil {
			t.Fatal("mismatched cover accepted")
		}
	}
	p.Target = "203.0.113.1:80"
	if err := p.Validate(); err == nil {
		t.Fatal("general proxy target accepted")
	}
}

func TestSupervisorRefusesUnverifiedOrUnrestrictedProcess(t *testing.T) {
	p := testProfile(t)
	data, _ := ClientJSON(p, "127.0.0.1:19090", "otu", strings.Repeat("x", 43))
	if _, err := Start(t.Context(), ProcessOptions{Mode: "client", Config: data, Listen: "127.0.0.1:19090", Target: p.Target, StateDir: t.TempDir(), Executable: "missing", SHA256: "bad"}); err == nil {
		t.Fatal("unverified companion launched")
	}
	if _, err := Start(t.Context(), ProcessOptions{Mode: "client", Config: []byte(`{"inbounds":[]}`), StateDir: t.TempDir()}); err == nil {
		t.Fatal("unrestricted companion launched")
	}
}

func FuzzRestrictedCompanionConfig(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"inbounds":[]}`))
	priv, password, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	id, err := GenerateUUID()
	if err != nil {
		f.Fatal(err)
	}
	short, err := GenerateShortID()
	if err != nil {
		f.Fatal(err)
	}
	client, err := ClientJSON(Profile{Version: 1, Endpoint: "127.0.0.1:19443", ServerName: "cover.test", UUID: id, Password: password, ShortID: short, Target: "127.0.0.1:18082"}, "127.0.0.1:19090", "otu", strings.Repeat("x", 43))
	if err != nil {
		f.Fatal(err)
	}
	server, err := ServerJSON(ServerParams{Listen: "127.0.0.1:19443", Target: "127.0.0.1:18082", CoverTarget: "127.0.0.1:18443", ServerName: "cover.test", PrivateKey: priv, UUIDs: []string{id}, ShortIDs: []string{short}, AllowLoopbackCover: true})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(client)
	f.Add(server)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		_ = ValidateClientJSON(data, "127.0.0.1:19090", "127.0.0.1:18082")
		_ = ValidateServerJSON(data, "127.0.0.1:19443", "127.0.0.1:18082")
	})
}
