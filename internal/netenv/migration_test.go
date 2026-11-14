package netenv

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func fullLegacyFixture(t *testing.T) (*Manager, *memorySettings, map[string]map[string]registryValue, []byte) {
	t.Helper()
	m, s := memoryManager(t)
	s.keys[regKeyPath] = map[string]registryValue{
		"ProxyEnable":   {Exists: true, Kind: 4, Integer: 0},
		"ProxyServer":   {Exists: true, Kind: 1, Text: "original-proxy.invalid:9000"},
		"ProxyOverride": {Exists: true, Kind: 1, Text: "original-bypass.invalid"},
		"AutoConfigURL": {Exists: true, Kind: 1, Text: "https://original.invalid/proxy.pac"},
	}
	legacy := snapshot{ProxyEnable: 0, ProxyServer: stringVal{Exists: true, Data: "original-proxy.invalid:9000"}, ProxyOverride: stringVal{Exists: true, Data: "original-bypass.invalid"}, AutoConfigURL: stringVal{Exists: true, Data: "https://original.invalid/proxy.pac"}, OtuAppliedServer: "127.0.0.1:18080", Policies: make(map[string]policySnap)}
	for i, path := range chromiumPolicyPaths {
		if i == 0 {
			s.keys[path] = map[string]registryValue{
				polMode:           {Exists: true, Kind: 1, Text: "system"},
				polServer:         {Exists: true, Kind: 1, Text: "original-policy.invalid:9000"},
				polBypass:         {Exists: true, Kind: 1, Text: "original-policy-bypass.invalid"},
				"UnrelatedPolicy": {Exists: true, Kind: 4, Integer: 99},
			}
			legacy.Policies[path] = policySnap{Mode: stringVal{Exists: true, Data: "system"}, Server: stringVal{Exists: true, Data: "original-policy.invalid:9000"}, Bypass: stringVal{Exists: true, Data: "original-policy-bypass.invalid"}, HadKey: true}
		} else {
			delete(s.keys, path)
			legacy.Policies[path] = policySnap{HadKey: false}
		}
	}
	before := copyKeys(s)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.snapPath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for path, values := range appliedSettings(legacy.OtuAppliedServer, []string{"synthetic.invalid", "*.fixture.invalid"}) {
		if s.keys[path] == nil {
			s.keys[path] = make(map[string]registryValue)
		}
		for name, value := range values {
			if value.Exists {
				s.keys[path][name] = value
			} else {
				delete(s.keys[path], name)
			}
		}
	}
	return m, s, before, raw
}

func TestFullLegacyPolicyDictionaryAndCustomBypassesMigrate(t *testing.T) {
	m, s, before, raw := fullLegacyFixture(t)
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	// Recovery deliberately reports nonfatal pending evidence after a
	// transient Windows file-sharing denial. Retry rather than equating a
	// nil mandatory error with complete optional cleanup.
	for attempt := 0; m.PendingPolicyCleanup() && attempt < 3; attempt++ {
		if err := m.Recover(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(s.keys, before) || m.PendingPolicyCleanup() {
		t.Fatal("complete v1.1.5 policy dictionary did not restore exactly")
	}
	archive := filepath.Join(m.Dir, "journal-imports", importedJournalID(raw)+".json")
	archived, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(archived, raw) {
		t.Fatal("original legacy evidence was not privately retained", err)
	}
}

func TestLegacyMandatoryPartialRestorePinsBypassAcrossRestart(t *testing.T) {
	m, s, before, _ := fullLegacyFixture(t)
	s.fail = func(path, name string, v registryValue) error {
		if path == regKeyPath && name == "ProxyOverride" && v.Text == "original-bypass.invalid" {
			return errors.New("synthetic legacy partial restore denial")
		}
		return nil
	}
	if err := m.Recover(); err == nil {
		t.Fatal("mandatory partial restore failure hidden")
	}
	state, err := readSnapshot(m.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 3 || state.LegacyBypass[regKeyPath] || state.Applied[regKeyPath]["ProxyOverride"].Text != "localhost;127.0.0.1;<local>;synthetic.invalid;*.fixture.invalid" {
		t.Fatal("unknown bypass was not resolved durably before ownership server restoration")
	}
	if s.keys[regKeyPath]["ProxyServer"].Text != "original-proxy.invalid:9000" {
		t.Fatal("fixture did not partly restore the server")
	}
	s.fail = nil
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("legacy partial restart recovery failed", err)
	}
}

func TestLegacyPendingPolicyPartialRestorePinsBypassAcrossRestart(t *testing.T) {
	m, s, before, _ := fullLegacyFixture(t)
	path := chromiumPolicyPaths[0]
	s.fail = func(p, name string, v registryValue) error {
		if p == path && name == polBypass && v.Text == "original-policy-bypass.invalid" {
			return errors.New("synthetic legacy optional partial restore denial")
		}
		return nil
	}
	if err := m.Recover(); err != nil || !m.PendingPolicyCleanup() {
		t.Fatal("optional legacy failure blocked startup or lost evidence", err)
	}
	for _, p := range pendingRecords(t, m) {
		b := p.Bundles[path]
		if b.LegacyBypass || b.Applied[polBypass].Text != "localhost,127.0.0.1,<local>,synthetic.invalid,*.fixture.invalid" {
			t.Fatal("legacy policy bypass was not durably pinned before partial restoration")
		}
	}
	s.fail = nil
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("legacy policy partial restart recovery failed", err)
	}
}

func TestLegacyBypassDoesNotOverrideDisabledOrReplacementPolicy(t *testing.T) {
	for _, replacementMode := range []string{"direct", "system", "fixed_servers"} {
		t.Run(replacementMode, func(t *testing.T) {
			m, s, _, _ := fullLegacyFixture(t)
			path := chromiumPolicyPaths[0]
			s.keys[path][polMode] = registryValue{Exists: true, Kind: 1, Text: replacementMode}
			if replacementMode == "fixed_servers" {
				s.keys[path][polServer] = registryValue{Exists: true, Kind: 1, Text: "replacement-policy.invalid:9001"}
			}
			replacement := cloneValues(s.keys[path])
			if err := m.Recover(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.keys[path], replacement) || !m.PendingPolicyCleanup() {
				t.Fatal("legacy bypass migration changed a policy bundle it no longer owned")
			}
		})
	}
}

func TestLegacyUnknownBypassDoesNotAcceptWrongType(t *testing.T) {
	m, s, _, _ := fullLegacyFixture(t)
	path := chromiumPolicyPaths[0]
	replacement := registryValue{Exists: true, Kind: 4, Integer: 99}
	s.keys[path][polBypass] = replacement
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	if !sameValue(s.keys[path][polBypass], replacement) || !m.PendingPolicyCleanup() {
		t.Fatal("legacy bypass exception accepted a non-applied value type")
	}
}

func TestLegacyPreAddressJournalNeverGuessesOwnership(t *testing.T) {
	m, s := memoryManager(t)
	writeLegacy(t, m, snapshot{ProxyEnable: 0, Policies: map[string]policySnap{
		chromiumPolicyPaths[0]: {HadKey: true},
	}})
	before := copyKeys(s)
	if err := m.Recover(); !errors.Is(err, ErrSettingsConflict) || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("pre-address recovery guessed settings ownership", err)
	}
	if _, err := readSnapshot(m.snapPath()); err != nil {
		t.Fatal("pre-address retained migration state cannot be decoded", err)
	}
	if err := m.RestoreFrom(m.snapPath()); err != nil {
		t.Fatal("explicit pre-address restore unavailable", err)
	}
}

func TestInvalidLegacyOwnerRecordIsNotTreatedAsDead(t *testing.T) {
	m, s, _, _ := fullLegacyFixture(t)
	if err := os.WriteFile(m.lockPath(), []byte("invalid owner"), 0600); err != nil {
		t.Fatal(err)
	}
	before := copyKeys(s)
	if err := m.Recover(); err == nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("unknown legacy owner was treated as absent/dead", err)
	}
}

func TestExactLegacyContaminationDoesNotRemoveOtherLocalProxy(t *testing.T) {
	for _, version := range []int{0, 2} {
		t.Run(map[int]string{0: "legacy-different-address", 2: "typed-exact-address"}[version], func(t *testing.T) {
			m, s := memoryManager(t)
			const independentProxy = "127.0.0.1:1080"
			if version == 0 {
				writeLegacy(t, m, snapshot{ProxyEnable: 1, ProxyServer: stringVal{Exists: true, Data: independentProxy}, ProxyOverride: stringVal{Exists: true, Data: "<local>;independent.invalid"}, OtuAppliedServer: "127.0.0.1:18080"})
				s.keys[regKeyPath] = appliedSettings("127.0.0.1:18080", nil)[regKeyPath]
			} else {
				s.keys[regKeyPath] = appliedSettings(independentProxy, nil)[regKeyPath]
				if err := m.Begin(independentProxy, nil); err != nil {
					t.Fatal(err)
				}
				state, err := readSnapshot(m.snapPath())
				if err != nil {
					t.Fatal(err)
				}
				state.Version, state.ID, state.Touched = 2, "", nil
				raw, _ := json.Marshal(state)
				if err := os.WriteFile(m.snapPath(), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.Recover(); err != nil {
				t.Fatal(err)
			}
			if s.keys[regKeyPath]["ProxyServer"].Text != independentProxy || s.keys[regKeyPath]["ProxyEnable"].Integer != 1 {
				t.Fatal("narrow legacy contamination rule removed another local proxy")
			}
		})
	}
}

func TestTypedV2RecoveryRemainsCompatible(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	if err := m.Begin("127.0.0.1:18080", []string{"synthetic.invalid"}); err != nil {
		t.Fatal(err)
	}
	state, err := readSnapshot(m.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	state.Version, state.ID, state.Touched = 2, "", nil
	raw, _ := json.Marshal(state)
	if err := os.WriteFile(m.snapPath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("typed v2 migration failed", err)
	}
}

func TestPendingDetachCrashWindowDoesNotLoseOriginals(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	state, err := readSnapshot(m.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.detachPolicies(state, false); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the durable pending copy but before active
	// journal deletion. Recovery must reuse, not overwrite, that evidence.
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("detached/active overlap recovery failed", err)
	}
}

func TestCorruptPendingAppliedEvidenceCannotTouchMandatorySettings(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.fail = func(path, name string, v registryValue) error {
		if policyPath(path) {
			return errors.New("synthetic policy restore denial")
		}
		return nil
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	for file, p := range pendingRecords(t, m) {
		p.Bundles[regKeyPath] = settingsBundle{Values: appliedSettings("unrelated.invalid:9999", nil)[regKeyPath]}
		raw, _ := json.Marshal(p)
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s.fail = nil
	before := copyKeys(s)
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("invalid pending journal wrote mandatory or optional settings", err)
	}
}

func TestExplicitBackupRestoreIsJournaledAcrossPartialFailure(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "settings-backup.json")
	raw, err := os.ReadFile(m.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	// Explicit force is authorized for this observed replacement, but not
	// for any different future administrator change during automatic retry.
	s.keys[regKeyPath]["ProxyServer"] = registryValue{Exists: true, Kind: 1, Text: "operator-replacement.invalid:9000"}
	s.keys[regKeyPath]["ProxyOverride"] = registryValue{Exists: true, Kind: 1, Text: "operator-replacement-bypass.invalid"}
	s.fail = func(path, name string, v registryValue) error {
		if path == regKeyPath && name == "ProxyOverride" && !v.Exists {
			return errors.New("synthetic partial explicit restore denial")
		}
		return nil
	}
	if err := m.RestoreFrom(backup); err == nil {
		t.Fatal("partial explicit restore failure was hidden")
	}
	state, err := readSnapshot(m.snapPath())
	if err != nil || state.Applied[regKeyPath]["ProxyServer"].Text != "operator-replacement.invalid:9000" {
		t.Fatal("force restore did not journal current ownership before mutation", err)
	}
	backupAfter, err := os.ReadFile(backup)
	if err != nil || !bytes.Equal(backupAfter, raw) {
		t.Fatal("explicit source backup was modified", err)
	}
	s.fail = nil
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("partial explicit restore could not be retried normally", err)
	}
}

func TestExplicitRestoreDoesNotDiscardADifferentActiveJournal(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "old-session.json")
	raw, err := os.ReadFile(m.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if err := m.Begin("127.0.0.1:19000", nil); err != nil {
		t.Fatal(err)
	}
	activeBefore, _ := os.ReadFile(m.snapPath())
	keysBefore := copyKeys(s)
	if err := m.RestoreFrom(backup); err == nil {
		t.Fatal("different active journal was replaced by explicit old backup")
	}
	activeAfter, _ := os.ReadFile(m.snapPath())
	if !bytes.Equal(activeAfter, activeBefore) || !reflect.DeepEqual(s.keys, keysBefore) {
		t.Fatal("different active session evidence or settings was overwritten")
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
}
