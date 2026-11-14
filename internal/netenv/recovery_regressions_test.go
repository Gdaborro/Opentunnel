package netenv

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// These six review reproductions are permanent invariants. Every adapter,
// address and journal is synthetic; tests never use the user's HKCU state.
func TestReviewOptionalRestoreKeepsRecoveryEvidence(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.fail = func(path, name string, v registryValue) error {
		if policyPath(path) {
			return errors.New("synthetic policy restore denied")
		}
		return nil
	}
	if err := m.Restore(); err != nil {
		t.Fatal("optional restore blocked mandatory recovery:", err)
	}
	if s.keys[chromiumPolicyPaths[0]][polServer].Text == "127.0.0.1:18080" && !m.PendingPolicyCleanup() {
		t.Fatal("policy still points to stopped local proxy, but its recovery evidence was deleted")
	}
}

type snapshotReadFault struct {
	settingsStore
	path, name string
	once       bool
}

func (s *snapshotReadFault) Read(path, name string) (registryValue, error) {
	if path == s.path && name == s.name && !s.once {
		s.once = true
		return registryValue{}, errors.New("synthetic transient snapshot read denial")
	}
	return s.settingsStore.Read(path, name)
}

func TestReviewUnreadablePolicySnapshotIsNotInventedAsAbsent(t *testing.T) {
	m, s := memoryManager(t)
	path := chromiumPolicyPaths[0]
	original := registryValue{Exists: true, Kind: 1, Text: "operator-proxy.invalid:9000"}
	s.keys[path][polServer] = original
	m.store = &snapshotReadFault{settingsStore: s, path: path, name: polServer}
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	if !sameValue(s.keys[path][polServer], original) {
		t.Fatal("unreadable bundle was mutated during apply")
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if !sameValue(s.keys[path][polServer], original) {
		t.Fatal("unreadable original policy was treated as absent and destroyed during restore")
	}
}

type concurrentPolicyChange struct {
	*memorySettings
	path        string
	reads       int
	replacement registryValue
}

func (s *concurrentPolicyChange) Read(path, name string) (registryValue, error) {
	if path == s.path && name == polServer {
		s.reads++
		if s.reads == 2 {
			s.keys[path][name] = s.replacement
		}
	}
	return s.memorySettings.Read(path, name)
}

func TestReviewOptionalApplyPreservesConcurrentPolicyChange(t *testing.T) {
	m, s := memoryManager(t)
	path := chromiumPolicyPaths[0]
	s.keys[path][polServer] = registryValue{Exists: true, Kind: 1, Text: "original-policy.invalid:8080"}
	replacement := registryValue{Exists: true, Kind: 1, Text: "new-operator-policy.invalid:9000"}
	m.store = &concurrentPolicyChange{memorySettings: s, path: path, replacement: replacement}
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	if !sameValue(s.keys[path][polServer], replacement) {
		t.Fatal("optional policy apply overwrote a concurrent operator policy")
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if !sameValue(s.keys[path][polServer], replacement) {
		t.Fatal("restore overwrote a skipped concurrent policy")
	}
}

func writeLegacy(t *testing.T, m *Manager, s snapshot) {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.snapPath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReviewLegacyBrowserCustomBypassIsRecoveredOrJournaled(t *testing.T) {
	m, s := memoryManager(t)
	path := chromiumPolicyPaths[0]
	writeLegacy(t, m, snapshot{ProxyEnable: 0, OtuAppliedServer: "127.0.0.1:18080", Policies: map[string]policySnap{
		path: {Mode: stringVal{Exists: true, Data: "system"}, HadKey: true},
	}})
	s.keys[regKeyPath] = appliedSettings("127.0.0.1:18080", []string{"synthetic.invalid"})[regKeyPath]
	s.keys[path] = appliedSettings("127.0.0.1:18080", []string{"synthetic.invalid"})[path]
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	if s.keys[path][polServer].Exists || s.keys[path][polMode].Text != "system" || m.PendingPolicyCleanup() {
		t.Fatal("journal-owned legacy browser custom bypass was not restored exactly")
	}
}

func TestReviewLegacyBypassExceptionRequiresOwnAppliedProxy(t *testing.T) {
	m, s := memoryManager(t)
	writeLegacy(t, m, snapshot{ProxyEnable: 0, ProxyServer: stringVal{Exists: true, Data: "operator-proxy.invalid:9000"}, ProxyOverride: stringVal{Exists: true, Data: "original-bypass.invalid"}, OtuAppliedServer: "127.0.0.1:18080"})
	replacement := registryValue{Exists: true, Kind: 1, Text: "new-operator-bypass.invalid"}
	s.keys[regKeyPath] = map[string]registryValue{
		"ProxyEnable":   {Exists: true, Kind: 4, Integer: 0},
		"ProxyServer":   {Exists: true, Kind: 1, Text: "operator-proxy.invalid:9000"},
		"ProxyOverride": replacement,
	}
	if err := m.Recover(); !errors.Is(err, ErrSettingsConflict) {
		t.Fatalf("ownership-ended legacy recovery error = %v", err)
	}
	if !sameValue(s.keys[regKeyPath]["ProxyOverride"], replacement) {
		t.Fatal("legacy bypass exception overwrote a changed bypass after applied ownership ended")
	}
}

func TestReviewLegacyContaminatedOriginalCannotRestoreDeadProxy(t *testing.T) {
	m, s := memoryManager(t)
	const deadProxy = "127.0.0.1:18080"
	writeLegacy(t, m, snapshot{ProxyEnable: 1, ProxyServer: stringVal{Exists: true, Data: deadProxy}, ProxyOverride: stringVal{Exists: true, Data: "localhost;127.0.0.1;<local>"}, OtuAppliedServer: deadProxy})
	s.keys[regKeyPath] = appliedSettings(deadProxy, nil)[regKeyPath]
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	if s.keys[regKeyPath]["ProxyEnable"].Integer != 0 || s.keys[regKeyPath]["ProxyServer"].Exists {
		t.Fatal("legacy recovery left its exactly contaminated stopped proxy enabled")
	}
}
