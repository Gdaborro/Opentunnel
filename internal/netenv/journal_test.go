package netenv

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

// These tests NEVER use HKCU or the actual Windows settings adapter.
type memorySettings struct {
	keys       map[string]map[string]registryValue
	fail       func(path, name string, v registryValue) error
	dropWrites bool
	writes     int
}

func (s *memorySettings) KeyExists(path string) (bool, error) { _, ok := s.keys[path]; return ok, nil }
func (s *memorySettings) Read(path, name string) (registryValue, error) {
	return s.keys[path][name], nil
}
func (s *memorySettings) Write(path, name string, v registryValue) error {
	if s.fail != nil {
		if err := s.fail(path, name, v); err != nil {
			return err
		}
	}
	if s.dropWrites {
		return nil
	}
	s.writes++
	if !v.Exists {
		if key := s.keys[path]; key != nil {
			delete(key, name)
		}
		return nil
	}
	if s.keys[path] == nil {
		s.keys[path] = make(map[string]registryValue)
	}
	s.keys[path][name] = v
	return nil
}
func (s *memorySettings) DeleteEmptyKey(path string) error {
	if len(s.keys[path]) == 0 {
		delete(s.keys, path)
	}
	return nil
}

func memoryManager(t *testing.T) (*Manager, *memorySettings) {
	t.Helper()
	s := &memorySettings{keys: map[string]map[string]registryValue{regKeyPath: {
		"ProxyServer":   {Exists: true, Kind: 1, Text: "original.test:8080"},
		"AutoConfigURL": {Exists: true, Kind: 2, Text: "%USERPROFILE%/original.pac"},
	}, chromiumPolicyPaths[0]: {"UnrelatedPolicy": {Exists: true, Kind: 4, Integer: 99}}}}
	m := &Manager{Dir: t.TempDir(), store: s, owner: func() (journalOwner, error) { return journalOwner{PID: 123, Created: 456}, nil }, ownerAlive: func(journalOwner) (bool, error) { return false, nil }}
	return m, s
}
func copyKeys(s *memorySettings) map[string]map[string]registryValue {
	out := make(map[string]map[string]registryValue)
	for path, values := range s.keys {
		out[path] = make(map[string]registryValue)
		for name, v := range values {
			out[path][name] = v
		}
	}
	return out
}

func TestJournalRoundTripPreservesMissingAndTypedValues(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.snapPath()); err != nil {
		t.Fatal("journal not created before mutation")
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.keys, before) {
		t.Fatalf("settings not restored exactly: %+v", s.keys)
	}
	if _, err := os.Stat(m.snapPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed journal not removed")
	}
}

func TestPartialApplyRollsBackBeforeReturning(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	s.fail = func(path, name string, v registryValue) error {
		if path == regKeyPath && name == "ProxyOverride" && v.Exists {
			return errors.New("synthetic apply failure")
		}
		return nil
	}
	if err := m.Begin("127.0.0.1:18080", nil); err == nil {
		t.Fatal("partial failure hidden")
	}
	if !reflect.DeepEqual(s.keys, before) {
		t.Fatal("partial apply did not roll back")
	}
	if _, err := os.Stat(m.snapPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful rollback retained an unnecessary journal")
	}
}

// Managed machines often make HKCU\Software\Policies read-only. v1.1.5
// treated those browser policy keys as best-effort; v1.1.6 must do the same
// or the client exits during --auto-proxy startup after an update.
func TestReadOnlyPolicyKeysDoNotBlockProxyApply(t *testing.T) {
	m, s := memoryManager(t)
	s.fail = func(path, name string, v registryValue) error {
		if policyPath(path) {
			return errors.New("synthetic access denied")
		}
		return nil
	}
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatalf("Begin with read-only policy keys: %v", err)
	}
	if got := s.keys[regKeyPath]["ProxyServer"].Text; got != "127.0.0.1:18080" {
		t.Fatalf("mandatory ProxyServer not applied: %q", got)
	}
	if _, err := os.Stat(m.snapPath()); err != nil {
		t.Fatal("journal not created before mutation")
	}
	if err := m.Restore(); err != nil {
		t.Fatalf("Restore with read-only policy keys: %v", err)
	}
	if got := s.keys[regKeyPath]["ProxyServer"].Text; got != "original.test:8080" {
		t.Fatalf("mandatory ProxyServer not restored: %q", got)
	}
	if _, err := os.Stat(m.snapPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("untouched read-only policies retained active session ownership")
	}
	if m.PendingPolicyCleanup() {
		t.Fatal("policies never changed by Begin should not require pending cleanup")
	}
}

func TestMandatoryProxyWriteStillFails(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	s.fail = func(path, name string, v registryValue) error {
		if path == regKeyPath && name == "ProxyServer" && v.Exists {
			return errors.New("synthetic access denied")
		}
		return nil
	}
	if err := m.Begin("127.0.0.1:18080", nil); err == nil {
		t.Fatal("denied mandatory ProxyServer write was accepted")
	}
	if !reflect.DeepEqual(s.keys, before) {
		t.Fatal("failed mandatory apply did not roll back")
	}
}

func TestPolicyRestoreFailureIsBestEffort(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.fail = func(path, name string, v registryValue) error {
		if policyPath(path) {
			return errors.New("synthetic denied policy restore")
		}
		return nil
	}
	if err := m.Restore(); err != nil {
		t.Fatalf("policy restore failure blocked main restore: %v", err)
	}
	if got := s.keys[regKeyPath]["ProxyServer"].Text; got != "original.test:8080" {
		t.Fatalf("mandatory ProxyServer not restored: %q", got)
	}
	if _, err := os.Stat(m.snapPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("optional cleanup blocked release of mandatory session ownership")
	}
	if !m.PendingPolicyCleanup() || len(m.LastResult().PendingPolicies) == 0 {
		t.Fatal("failed optional cleanup discarded recovery evidence or its warning")
	}
	s.fail = nil
	if err := m.Recover(); err != nil {
		t.Fatal(err)
	}
	if m.PendingPolicyCleanup() {
		t.Fatal("successful optional retry retained unnecessary cleanup evidence")
	}
}

// A v1.1.5 updater exits with os.Exit after swapping binaries, leaving its
// legacy journal and system proxy behind. The legacy journal records the
// applied server but not the config-specific bypass list, so recovery must
// not mistake that bypass list for a third-party change.
func TestLegacyJournalWithCustomBypassRecovers(t *testing.T) {
	m, s := memoryManager(t)
	s.keys[regKeyPath] = map[string]registryValue{
		"ProxyEnable": {Exists: true, Kind: 4, Integer: 0},
	}
	legacy := `{"proxy_enable":0,"proxy_server":{"exists":false},"proxy_override":{"exists":false},"autoconfig_url":{"exists":false},"policies":{},"otu_applied_server":"127.0.0.1:18080"}`
	if err := os.WriteFile(m.snapPath(), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.lockPath(), []byte("99999"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.keys[regKeyPath] = map[string]registryValue{
		"ProxyEnable":   {Exists: true, Kind: 4, Integer: 1},
		"ProxyServer":   {Exists: true, Kind: 1, Text: "127.0.0.1:18080"},
		"ProxyOverride": {Exists: true, Kind: 1, Text: "localhost;127.0.0.1;<local>;cdn.aborro.dev;*.aborro.dev;localhost;127.0.0.1"},
	}
	if err := m.Recover(); err != nil {
		t.Fatalf("legacy journal recovery: %v", err)
	}
	if got := s.keys[regKeyPath]["ProxyEnable"].Integer; got != 0 {
		t.Fatalf("ProxyEnable not restored: %d", got)
	}
	if s.keys[regKeyPath]["ProxyServer"].Exists {
		t.Fatal("ProxyServer not restored to absent")
	}
	if s.keys[regKeyPath]["ProxyOverride"].Exists {
		t.Fatal("ProxyOverride not restored to absent")
	}
	if _, err := os.Stat(m.snapPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovered legacy journal was retained")
	}
}

// Legacy recovery must still refuse to overwrite a replacement proxy server.
func TestLegacyJournalDoesNotOverwriteReplacementProxy(t *testing.T) {
	m, s := memoryManager(t)
	s.keys[regKeyPath] = map[string]registryValue{
		"ProxyEnable": {Exists: true, Kind: 4, Integer: 0},
	}
	legacy := `{"proxy_enable":0,"proxy_server":{"exists":false},"proxy_override":{"exists":false},"autoconfig_url":{"exists":false},"policies":{},"otu_applied_server":"127.0.0.1:18080"}`
	if err := os.WriteFile(m.snapPath(), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.lockPath(), []byte("99999"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.keys[regKeyPath] = map[string]registryValue{
		"ProxyEnable":   {Exists: true, Kind: 4, Integer: 1},
		"ProxyServer":   {Exists: true, Kind: 1, Text: "user-replacement.test:9000"},
		"ProxyOverride": {Exists: true, Kind: 1, Text: "localhost;127.0.0.1;<local>"},
	}
	if err := m.Recover(); !errors.Is(err, ErrSettingsConflict) {
		t.Fatalf("replacement proxy conflict=%v", err)
	}
	if got := s.keys[regKeyPath]["ProxyServer"].Text; got != "user-replacement.test:9000" {
		t.Fatalf("replacement proxy overwritten: %q", got)
	}
	if _, err := os.Stat(m.snapPath()); err != nil {
		t.Fatal("conflict journal not retained")
	}
}

func TestFailedRestoreRetainsRetryableJournal(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.fail = func(path, name string, v registryValue) error {
		if path == regKeyPath && name == "ProxyServer" && v.Text == "original.test:8080" {
			return errors.New("synthetic denied restore")
		}
		return nil
	}
	if err := m.Restore(); err == nil {
		t.Fatal("restore failure hidden")
	}
	if _, err := os.Stat(m.snapPath()); err != nil {
		t.Fatal("last recovery journal was deleted after failed restore")
	}
	if s.keys[regKeyPath]["ProxyEnable"].Exists {
		t.Fatal("a denied server restore prevented disabling the journal-owned proxy")
	}
	for _, path := range chromiumPolicyPaths {
		if !reflect.DeepEqual(s.keys[path], before[path]) {
			t.Fatal("mandatory restoration failure prevented independent policy cleanup")
		}
	}
	s.fail = nil
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.keys, before) {
		t.Fatal("retry did not restore exact state")
	}
}

func TestExternalProxyChangeIsNotOverwritten(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.keys[regKeyPath]["ProxyServer"] = registryValue{Exists: true, Kind: 1, Text: "user-replacement.test:9000"}
	if err := m.Restore(); !errors.Is(err, ErrSettingsConflict) {
		t.Fatalf("conflict=%v", err)
	}
	if s.keys[regKeyPath]["ProxyServer"].Text != "user-replacement.test:9000" || s.keys[regKeyPath]["ProxyEnable"].Integer != 1 {
		t.Fatal("external settings bundle was modified")
	}
	if _, err := os.Stat(m.snapPath()); err != nil {
		t.Fatal("conflict journal not retained")
	}
	// Explicit restore-from is the operator's force-restore path.
	if err := m.RestoreFrom(m.snapPath()); err != nil {
		t.Fatal(err)
	}
	if s.keys[regKeyPath]["ProxyServer"].Text != "original.test:8080" {
		t.Fatal("explicit recovery did not restore backup")
	}
}

func TestLiveOwnerAndCorruptJournalAreProtected(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	other := &Manager{Dir: m.Dir, store: s, ownerAlive: func(journalOwner) (bool, error) { return true, nil }}
	writes := s.writes
	if err := other.Recover(); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal(err)
	}
	if err := other.Restore(); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal(err)
	}
	if s.writes != writes {
		t.Fatal("another live owner's settings changed")
	}
	if err := os.WriteFile(m.snapPath(), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(); err == nil {
		t.Fatal("incomplete journal accepted")
	}
	if s.writes != writes {
		t.Fatal("corrupt journal triggered registry writes")
	}
}

func TestJournalCannotRestoreUnrelatedRegistryPaths(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	snap, err := readSnapshot(m.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	snap.Values[`Software\UnrelatedApplication`] = map[string]registryValue{"secret": {Exists: true, Kind: 1, Text: "unrelated"}}
	raw, _ := json.Marshal(snap)
	_ = os.WriteFile(m.snapPath(), raw, 0o600)
	writes := s.writes
	if err := m.Restore(); err == nil {
		t.Fatal("unrelated path was accepted")
	}
	if s.writes != writes {
		t.Fatal("invalid journal touched settings")
	}
}

func TestBeginCannotOverwriteExistingJournal(t *testing.T) {
	m, _ := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.snapPath())
	if err := m.Begin("127.0.0.1:19000", nil); err == nil {
		t.Fatal("nested begin replaced original journal")
	}
	after, _ := os.ReadFile(m.snapPath())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("original journal overwritten")
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
}

func FuzzJournalDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":999}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"proxy_enable":0,"proxy_server":{"exists":false},"proxy_override":{"exists":false},"autoconfig_url":{"exists":false},"otu_applied_server":"127.0.0.1:18080"}`))
	values := appliedSettings("127.0.0.1:18080", []string{"synthetic.invalid"})
	s := snapshot{Version: 3, ID: "00000000000000000000000000000000", Owner: journalOwner{PID: 123}, Values: values, Applied: values, HadKeys: make(map[string]bool), Touched: make(map[string]bool)}
	for path := range values {
		s.HadKeys[path], s.Touched[path] = true, true
	}
	raw, _ := json.Marshal(s)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			return
		}
		path := t.TempDir() + "/journal.json"
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = readSnapshot(path)
	})
}

func TestIncompleteTypedJournalCannotDeleteExistingKeys(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	state, err := readSnapshot(m.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	delete(state.HadKeys, chromiumPolicyPaths[0])
	raw, _ := json.Marshal(state)
	_ = os.WriteFile(m.snapPath(), raw, 0o600)
	writes := s.writes
	if err := m.Restore(); err == nil {
		t.Fatal("incomplete key-existence snapshot accepted")
	}
	if s.writes != writes {
		t.Fatal("incomplete snapshot modified settings")
	}
}

func TestSuccessfulReturnWithoutRestorationRetainsJournal(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.dropWrites = true
	if err := m.Restore(); err == nil {
		t.Fatal("registry adapter success was mistaken for durable restoration")
	}
	if _, err := os.Stat(m.snapPath()); err != nil {
		t.Fatal("failed verified restore deleted recovery journal")
	}
	s.dropWrites = false
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
}
