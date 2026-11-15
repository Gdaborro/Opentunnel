package serverpool

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testProfile(t *testing.T) (Profile, ed25519.PrivateKey, time.Time) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	p := Profile{Name: "Synthetic operator", AuthorityID: strings.Repeat("a", 64), IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(time.Hour).Unix(), ApprovalRequired: true,
		Nodes: []Node{{ID: "entry-a", Name: "Entry A", Address: "entry.example:8443", DialAddress: "192.0.2.1:443", Pins: []string{strings.Repeat("b", 64)}, WSPath: "/api/v1/stream"}}}
	if err := p.Sign(key, now); err != nil {
		t.Fatal(err)
	}
	return p, key, now
}

func copyProfile(p Profile) Profile {
	raw, _ := json.Marshal(p)
	var copy Profile
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func TestSignedProfileContract(t *testing.T) {
	p, _, now := testProfile(t)
	raw, _ := json.Marshal(p)
	decoded, err := Decode(raw)
	if err != nil || decoded.Verify(now) != nil {
		t.Fatalf("round trip: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Profile)
	}{
		{"unsigned", func(p *Profile) { p.Signature = "" }},
		{"different operator", func(p *Profile) { p.ID = strings.Repeat("f", 64) }},
		{"authority", func(p *Profile) { p.AuthorityID = strings.Repeat("c", 64) }},
		{"node redirect", func(p *Profile) { p.Nodes[0].Address = "other.example:443" }},
		{"pin replacement", func(p *Profile) { p.Nodes[0].Pins[0] = strings.Repeat("c", 64) }},
		{"login policy", func(p *Profile) { p.LoginRequired = true }},
		{"automatic approval", func(p *Profile) { p.ApprovalRequired = false }},
		{"expiry", func(p *Profile) { p.ExpiresAt = now.Unix() }},
		{"excess validity", func(p *Profile) { p.ExpiresAt = p.IssuedAt + int64(MaxValidity/time.Second) + 1 }},
		{"future", func(p *Profile) { p.IssuedAt = now.Add(6 * time.Minute).Unix() }},
		{"control label", func(p *Profile) { p.Name = "Operator\u202e" }},
		{"userinfo endpoint", func(p *Profile) { p.Nodes[0].Address = "user:pass@entry.example:443" }},
		{"nonliteral dial override", func(p *Profile) { p.Nodes[0].DialAddress = "other.example:443" }},
		{"ambiguous port", func(p *Profile) { p.Nodes[0].Address = "entry.example:0443" }},
		{"empty pins", func(p *Profile) { p.Nodes[0].Pins = nil }},
		{"duplicate pins", func(p *Profile) { p.Nodes[0].Pins = append(p.Nodes[0].Pins, p.Nodes[0].Pins[0]) }},
		{"duplicate node", func(p *Profile) { p.Nodes = append(p.Nodes, p.Nodes[0]) }},
		{"path query", func(p *Profile) { p.Nodes[0].WSPath = "/stream?password=secret" }},
		{"unicode path", func(p *Profile) { p.Nodes[0].WSPath = "/stream\u200b" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := copyProfile(p)
			tc.change(&changed)
			if changed.Verify(now) == nil {
				t.Fatal("changed trust document accepted")
			}
		})
	}
	if p.Nodes[0].DialAddr() != "192.0.2.1:443" || p.Nodes[0].ServerName() != "entry.example" {
		t.Fatal("TCP override changed trusted authority")
	}
	node := p.Nodes[0]
	node.Address = "other.example:443"
	if p.ContainsNode(node) {
		t.Fatal("matching ID authorized a different endpoint")
	}
}

func TestProfileRejectsAmbiguousOrCredentialBearingJSON(t *testing.T) {
	p, _, _ := testProfile(t)
	raw, _ := json.Marshal(p)
	for _, data := range []string{
		"null", string(raw) + " null", string(raw) + " {}",
		strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(raw), `"version":1`, `"Version":1`, 1),
		strings.Replace(string(raw), `"name":"Synthetic operator"`, `"name":"Synthetic operator","password":"do-not-import"`, 1),
		strings.Replace(string(raw), `"login_required":false`, `"login_required":null`, 1),
		strings.Replace(string(raw), `"pins":[`, `"username":"not-allowed","pins":[`, 1),
	} {
		if _, err := Decode([]byte(data)); err == nil {
			t.Fatalf("ambiguous/credential document accepted: %.60s", data)
		}
	}
	if _, err := Decode(make([]byte, MaxProfileSize+1)); err == nil {
		t.Fatal("oversized profile accepted")
	}
}

func TestPoolStoreConsentRollbackAndSelection(t *testing.T) {
	p, key, now := testProfile(t)
	s := Store{Dir: t.TempDir()}
	if id, err := s.Selected(); err != nil || id != "default" {
		t.Fatal(id, err)
	}
	if err := s.Import(p, false, now); err == nil {
		t.Fatal("self-signature accepted without consent")
	}
	if err := s.Import(p, true, now); err != nil {
		t.Fatal(err)
	}
	if id, _ := s.Selected(); id != "default" {
		t.Fatal("import silently switched operators")
	}
	if err := s.Select(p.ID, now); err != nil {
		t.Fatal(err)
	}
	newer := copyProfile(p)
	newer.IssuedAt++
	newer.ExpiresAt++
	if err := newer.Sign(key, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Import(newer, true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Import(p, true, now); err == nil {
		t.Fatal("signed rollback accepted")
	}
	conflict := copyProfile(newer)
	conflict.Name = "Conflicting signed name"
	_ = conflict.Sign(key, now)
	if err := s.Import(conflict, true, now); err == nil {
		t.Fatal("same-version conflicting update accepted")
	}
	if err := s.Import(newer, true, now); err != nil {
		t.Fatal("idempotent import failed", err)
	}
	wrongAuthority := copyProfile(newer)
	wrongAuthority.IssuedAt++
	wrongAuthority.AuthorityID = strings.Repeat("c", 64)
	_ = wrongAuthority.Sign(key, now)
	if err := s.Import(wrongAuthority, true, now); err == nil {
		t.Fatal("approval authority silently replaced")
	}
	if _, err := s.Load(newer.ID, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired profile connected")
	}
	if list, err := s.List(now.Add(2 * time.Hour)); err != nil || len(list) != 1 {
		t.Fatal("expired inventory hidden", err)
	}
	if err := s.Select("default", now); err != nil {
		t.Fatal(err)
	}
}

func TestPoolStoreRejectsCorruptSelectionAndMisnamedProfiles(t *testing.T) {
	p, _, now := testProfile(t)
	s := Store{Dir: t.TempDir()}
	for _, raw := range []string{`null`, `{"id":"default"} {}`, `{"id":"default","id":"default"}`, `{"ID":"default"}`, `{"id":null}`} {
		if err := os.WriteFile(filepath.Join(s.Dir, "selected-server-pool.json"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Selected(); err == nil {
			t.Fatal("corrupt selection used", raw)
		}
	}
	wrong := strings.Repeat("f", 64)
	if err := os.Mkdir(filepath.Join(s.Dir, "server-profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(s.Dir, "server-profiles", wrong+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(wrong, now); err == nil {
		t.Fatal("requested ID did not match profile")
	}
	if _, err := s.List(now); err == nil {
		t.Fatal("misnamed profile accepted in inventory")
	}
}

func TestPoolStoreConcurrentUpdatesCannotRollback(t *testing.T) {
	p, key, now := testProfile(t)
	s := Store{Dir: t.TempDir()}
	if err := s.Import(p, true, now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 16 {
		updated := copyProfile(p)
		updated.IssuedAt += int64(i + 1)
		updated.ExpiresAt += int64(i + 1)
		_ = updated.Sign(key, now)
		wg.Go(func() { _ = s.Import(updated, true, now) })
	}
	wg.Wait()
	latest, err := s.Load(p.ID, now)
	if err != nil || latest.IssuedAt != p.IssuedAt+16 {
		t.Fatal("concurrent trust update rolled back", err)
	}
}

func TestPoolStoreBoundsDirectoryEnumeration(t *testing.T) {
	p, _, now := testProfile(t)
	s := Store{Dir: t.TempDir()}
	dir := filepath.Join(s.Dir, "server-profiles")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := range MaxProfiles + 1 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("junk-%d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.List(now); err == nil {
		t.Fatal("unbounded inventory accepted")
	}
	if err := s.Import(p, true, now); err == nil {
		t.Fatal("import exceeded directory capacity")
	}
}

func TestOperatorKeyAndExportNeverOverwrite(t *testing.T) {
	p, _, now := testProfile(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "dedicated-key.pem")
	id, err := GenerateOperatorKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := LoadOperatorKey(keyPath)
	if err != nil || OperatorID(key.Public().(ed25519.PublicKey)) != id {
		t.Fatal("operator identity changed", err)
	}
	if _, err := GenerateOperatorKey(keyPath); err == nil {
		t.Fatal("private operator key overwritten")
	}
	p.ID = ""
	p.OperatorKey = ""
	if err := p.Sign(key, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pool.json")
	if err := Export(path, p, now); err != nil {
		t.Fatal(err)
	}
	if err := Export(path, p, now); err == nil {
		t.Fatal("export overwrote existing work")
	}
	if loaded, err := Load(path, now); err != nil || loaded.ID != id {
		t.Fatal("export verification failed", err)
	}
}
