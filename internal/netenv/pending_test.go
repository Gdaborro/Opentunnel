package netenv

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

type hookedSettings struct {
	*memorySettings
	readHook   func(path, name string) error
	keyHook    func(path string) error
	beforeRead func(path, name string)
	afterWrite func(path, name string)
	deleteHook func(path string) error
}

func (s *hookedSettings) Read(path, name string) (registryValue, error) {
	if s.beforeRead != nil {
		s.beforeRead(path, name)
	}
	if s.readHook != nil {
		if err := s.readHook(path, name); err != nil {
			return registryValue{}, err
		}
	}
	return s.memorySettings.Read(path, name)
}

func (s *hookedSettings) KeyExists(path string) (bool, error) {
	if s.keyHook != nil {
		if err := s.keyHook(path); err != nil {
			return false, err
		}
	}
	return s.memorySettings.KeyExists(path)
}

func (s *hookedSettings) Write(path, name string, v registryValue) error {
	if err := s.memorySettings.Write(path, name, v); err != nil {
		return err
	}
	if s.afterWrite != nil {
		s.afterWrite(path, name)
	}
	return nil
}

func (s *hookedSettings) DeleteEmptyKey(path string) error {
	if s.deleteHook != nil {
		if err := s.deleteHook(path); err != nil {
			return err
		}
	}
	return s.memorySettings.DeleteEmptyKey(path)
}

func restartManager(m *Manager) *Manager {
	return &Manager{Dir: m.Dir, store: m.store, owner: m.owner, ownerAlive: m.ownerAlive, leaseFactory: m.leaseFactory}
}

func pendingRecords(t *testing.T, m *Manager) map[string]pendingPolicies {
	t.Helper()
	files, err := m.pendingFiles()
	if err != nil {
		t.Fatal(err)
	}
	records := make(map[string]pendingPolicies)
	for _, file := range files {
		p, err := readPending(file)
		if err != nil {
			t.Fatal(err)
		}
		records[file] = p
	}
	return records
}

func TestPendingPoliciesSurviveRestartsWithoutBlockingBegin(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	if err := m.Begin("127.0.0.1:18080", []string{"synthetic.invalid"}); err != nil {
		t.Fatal(err)
	}
	s.fail = func(path, name string, v registryValue) error {
		if policyPath(path) {
			return errors.New("synthetic restore access denied")
		}
		return nil
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if m.leaseRelease != nil {
		t.Fatal("optional cleanup retained the active lease")
	}
	if _, err := os.Stat(m.snapPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("active journal was not detached")
	}
	originalRecords := pendingRecords(t, m)
	if len(originalRecords) != 1 {
		t.Fatal("missing per-session pending policy evidence")
	}
	next := restartManager(m)
	if err := next.Recover(); err != nil {
		t.Fatal("pending policy denial blocked recovery:", err)
	}
	if err := next.Begin("127.0.0.1:19000", nil); err != nil {
		t.Fatal("pending policies blocked mandatory next startup:", err)
	}
	active, err := readSnapshot(next.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range chromiumPolicyPaths {
		if _, captured := active.Values[path]; captured {
			t.Fatal("pending policy was captured as the next session's original")
		}
		if s.keys[path][polServer].Text != "127.0.0.1:18080" {
			t.Fatal("pending policy was overwritten by the next session")
		}
	}
	if err := next.Restore(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pendingRecords(t, next), originalRecords) {
		t.Fatal("new session replaced unresolved recovery evidence")
	}
	s.fail = nil
	final := restartManager(next)
	if err := final.Recover(); err != nil {
		t.Fatal(err)
	}
	if final.PendingPolicyCleanup() || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("permissions-returned retry did not restore the exact originals")
	}
}

func TestOnlyUnresolvedPolicyBundlesAreSkippedNextBegin(t *testing.T) {
	m, s := memoryManager(t)
	blockedPath := chromiumPolicyPaths[0]
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.fail = func(path, name string, v registryValue) error {
		if path == blockedPath {
			return errors.New("synthetic one-policy restore denial")
		}
		return nil
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	next := restartManager(m)
	if err := next.Begin("127.0.0.1:19000", nil); err != nil {
		t.Fatal(err)
	}
	state, err := readSnapshot(next.snapPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, captured := state.Values[blockedPath]; captured || len(state.Values) != len(settingsPaths())-1 {
		t.Fatal("an isolated pending policy blocked unrelated optional bundles")
	}
	if err := next.Restore(); err != nil {
		t.Fatal(err)
	}
	s.fail = nil
	if err := restartManager(next).Recover(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownOptionalBundlesAreSkippedCompletely(t *testing.T) {
	for _, fault := range []string{"key", polServer, polBypass, polMode} {
		t.Run(fault, func(t *testing.T) {
			m, s := memoryManager(t)
			path := chromiumPolicyPaths[0]
			s.keys[path][polServer] = registryValue{Exists: true, Kind: 2, Text: "%OPERATOR_PROXY%"}
			s.keys[path][polMode] = registryValue{Exists: true, Kind: 1, Text: "system"}
			before := cloneValues(s.keys[path])
			faulted := false
			h := &hookedSettings{memorySettings: s}
			if fault == "key" {
				h.keyHook = func(p string) error {
					if p == path && !faulted {
						faulted = true
						return errors.New("synthetic unreadable key")
					}
					return nil
				}
			} else {
				h.readHook = func(p, name string) error {
					if p == path && name == fault && !faulted {
						faulted = true
						return errors.New("synthetic transient unreadable value")
					}
					return nil
				}
			}
			m.store = h
			if err := m.Begin("127.0.0.1:18080", nil); err != nil {
				t.Fatal(err)
			}
			active, err := readSnapshot(m.snapPath())
			if err != nil {
				t.Fatal(err)
			}
			if _, captured := active.Values[path]; captured || !reflect.DeepEqual(s.keys[path], before) {
				t.Fatal("an unknown policy bundle was partly journaled or written")
			}
			if len(m.LastResult().SkippedPolicies) == 0 || len(m.LastResult().Warnings) == 0 {
				t.Fatal("unknown bundle skip was silent")
			}
			if err := m.Restore(); err != nil || !reflect.DeepEqual(s.keys[path], before) {
				t.Fatal("restore touched an unknown skipped bundle", err)
			}
		})
	}
}

func TestPartialOptionalApplyRollsBackKnownOriginals(t *testing.T) {
	for _, failedName := range []string{polBypass, polMode} {
		t.Run(failedName, func(t *testing.T) {
			m, s := memoryManager(t)
			before := copyKeys(s)
			path := chromiumPolicyPaths[0]
			s.fail = func(p, name string, v registryValue) error {
				if p == path && name == failedName && v.Exists {
					return errors.New("synthetic partial policy apply denial")
				}
				return nil
			}
			if err := m.Begin("127.0.0.1:18080", nil); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s.keys[path], before[path]) {
				t.Fatal("partially applied policy was not rolled back")
			}
			state, err := readSnapshot(m.snapPath())
			if err != nil || state.Touched[path] {
				t.Fatal("completed partial rollback retained policy ownership", err)
			}
			if err := m.Restore(); err != nil || !reflect.DeepEqual(s.keys, before) {
				t.Fatal("mandatory startup/restore was affected by optional partial apply", err)
			}
		})
	}
}

func TestPartialOptionalRollbackDenialRemainsRetryable(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	path := chromiumPolicyPaths[0]
	s.fail = func(p, name string, v registryValue) error {
		if p == path && ((name == polBypass && v.Exists) || (name == polServer && !v.Exists)) {
			return errors.New("synthetic partial apply and rollback denial")
		}
		return nil
	}
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	if len(m.LastResult().PendingPolicies) == 0 {
		t.Fatal("partial rollback failure not reported")
	}
	if err := m.Restore(); err != nil || !m.PendingPolicyCleanup() {
		t.Fatal("partial rollback failure lost evidence or blocked mandatory restore", err)
	}
	s.fail = nil
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("partial rollback could not be recovered after restart", err)
	}
}

func TestOptionalApplyReadbackFailureRollsBackAndWarns(t *testing.T) {
	m, s := memoryManager(t)
	path := chromiumPolicyPaths[0]
	before := cloneValues(s.keys[path])
	wrote, faulted := false, false
	h := &hookedSettings{memorySettings: s}
	h.afterWrite = func(p, name string) {
		if p == path && name == polServer {
			wrote = true
		}
	}
	h.readHook = func(p, name string) error {
		if p == path && name == polServer && wrote && !faulted {
			faulted = true
			return errors.New("synthetic uncertain policy write readback")
		}
		return nil
	}
	m.store = h
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.keys[path], before) || len(m.LastResult().Warnings) == 0 {
		t.Fatal("optional readback failure was silent or did not roll back")
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
}

func TestCompetingChangesMidApplyAndMidRestoreArePreserved(t *testing.T) {
	for _, restoring := range []bool{false, true} {
		t.Run(map[bool]string{false: "apply", true: "restore"}[restoring], func(t *testing.T) {
			m, s := memoryManager(t)
			path := chromiumPolicyPaths[0]
			h := &hookedSettings{memorySettings: s}
			m.store = h
			if restoring {
				if err := m.Begin("127.0.0.1:18080", nil); err != nil {
					t.Fatal(err)
				}
			}
			replacement := registryValue{Exists: true, Kind: 1, Text: "new-administrator-bypass.invalid"}
			changed := false
			h.afterWrite = func(p, name string) {
				if p == path && name == polServer && !changed {
					changed = true
					s.keys[path][polBypass] = replacement
				}
			}
			if restoring {
				if err := m.Restore(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := m.Begin("127.0.0.1:18080", nil); err != nil {
					t.Fatal(err)
				}
				if err := m.Restore(); err != nil {
					t.Fatal(err)
				}
			}
			if !sameValue(s.keys[path][polBypass], replacement) || !m.PendingPolicyCleanup() {
				t.Fatal("mid-bundle competing change overwritten or conflict evidence lost")
			}
			beforeRetry := cloneValues(s.keys[path])
			if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys[path], beforeRetry) {
				t.Fatal("restart overwrote the competing policy bundle", err)
			}
		})
	}
}

func TestPartialPendingRestoreSurvivesAnotherRestart(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	path := chromiumPolicyPaths[0]
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.fail = func(p, name string, v registryValue) error {
		if p == path && name == polBypass && !v.Exists {
			return errors.New("synthetic partial restore denial")
		}
		return nil
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	if s.keys[path][polServer].Exists || !s.keys[path][polBypass].Exists || !m.PendingPolicyCleanup() {
		t.Fatal("fixture did not exercise partial restoration")
	}
	s.fail = nil
	next := restartManager(m)
	if err := next.Recover(); err != nil || next.PendingPolicyCleanup() || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("partial pending retry failed", err)
	}
}

func TestCreatedEmptyPolicyKeyDeletionFailureIsPending(t *testing.T) {
	m, s := memoryManager(t)
	before := copyKeys(s)
	path := chromiumPolicyPaths[1]
	h := &hookedSettings{memorySettings: s, deleteHook: func(p string) error {
		if p == path {
			return errors.New("synthetic empty-key deletion denied")
		}
		return nil
	}}
	m.store = h
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(); err != nil || !m.PendingPolicyCleanup() {
		t.Fatal("failed empty-key cleanup was discarded", err)
	}
	if len(s.keys[path]) != 0 {
		t.Fatal("proxy values were not cleared before key cleanup")
	}
	h.deleteHook = nil
	if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
		t.Fatal("empty-key retry failed", err)
	}
}

func TestPendingPersistenceFailureRetainsActiveJournal(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.pendingDir(), []byte("synthetic obstruction"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(); err == nil {
		t.Fatal("pending evidence persistence failure hidden")
	}
	if _, err := os.Stat(m.snapPath()); err != nil {
		t.Fatal("active journal deleted without a durable pending copy")
	}
	if s.keys[regKeyPath]["ProxyServer"].Text != "original.test:8080" {
		t.Fatal("optional persistence failure prevented mandatory restoration")
	}
	if err := os.Remove(m.pendingDir()); err != nil { // only our exact obstruction file
		t.Fatal(err)
	}
	if err := m.Restore(); err != nil || m.PendingPolicyCleanup() {
		t.Fatal("retry after persistence repair failed", err)
	}
}

func TestPendingRestoreReadAndReadbackFailuresRemainRetryable(t *testing.T) {
	for _, stage := range []string{"read", "readback"} {
		t.Run(stage, func(t *testing.T) {
			m, s := memoryManager(t)
			before := copyKeys(s)
			path := chromiumPolicyPaths[0]
			h := &hookedSettings{memorySettings: s}
			m.store = h
			if err := m.Begin("127.0.0.1:18080", nil); err != nil {
				t.Fatal(err)
			}
			written := false
			h.afterWrite = func(p, name string) {
				if p == path && name == polServer {
					written = true
				}
			}
			h.readHook = func(p, name string) error {
				if p == path && (stage == "read" || written) {
					return errors.New("synthetic optional restore read denied")
				}
				return nil
			}
			if err := m.Restore(); err != nil || !m.PendingPolicyCleanup() || len(m.LastResult().Warnings) == 0 {
				t.Fatal("optional read/readback failure lost retry evidence", err)
			}
			h.readHook, h.afterWrite = nil, nil
			if err := restartManager(m).Recover(); err != nil || !reflect.DeepEqual(s.keys, before) {
				t.Fatal("optional read/readback retry failed", err)
			}
		})
	}
}

func TestDuplicatePendingPolicyClaimsAreNotApplied(t *testing.T) {
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
		t.Fatal(err)
	}
	for _, p := range pendingRecords(t, m) {
		p.Session = "ffffffffffffffffffffffffffffffff"
		raw, _ := encodePending(p)
		if err := os.WriteFile(m.pendingPath(p.Session), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s.fail = nil
	before := copyKeys(s)
	next := restartManager(m)
	if err := next.Recover(); err != nil || !reflect.DeepEqual(s.keys, before) || !next.PendingPolicyCleanup() {
		t.Fatal("ambiguous pending ownership wrote settings or discarded evidence", err)
	}
}

func TestCorruptPendingRecordDoesNotBlockMandatoryNewSession(t *testing.T) {
	m, s := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	s.fail = func(path, name string, v registryValue) error {
		if policyPath(path) {
			return errors.New("synthetic denied restore")
		}
		return nil
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	for file := range pendingRecords(t, m) {
		if err := os.WriteFile(file, []byte(`{"version":999}`), 0600); err != nil {
			t.Fatal(err)
		}
		before := copyKeys(s)
		s.fail = nil
		next := restartManager(m)
		if err := next.Recover(); err != nil {
			t.Fatal("corrupt optional state blocked mandatory recovery", err)
		}
		if !reflect.DeepEqual(s.keys, before) {
			t.Fatal("corrupt pending evidence triggered policy writes")
		}
		if err := next.Begin("127.0.0.1:19000", nil); err != nil {
			t.Fatal("corrupt optional state blocked mandatory Begin", err)
		}
		state, err := readSnapshot(next.snapPath())
		if err != nil || len(state.Values) != 1 {
			t.Fatal("ambiguous optional bundles were not all skipped", err)
		}
		if err := next.Restore(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(raw, []byte(`{"version":999}`)) {
			t.Fatal("corrupt optional evidence was discarded or overwritten", err)
		}
	}
}

func TestPendingRecordsDoNotRaceActiveLeaseOwner(t *testing.T) {
	m, s := memoryManager(t)
	held := false
	m.leaseFactory = func(string) (func(), error) {
		if held {
			return nil, ErrAlreadyRunning
		}
		held = true
		return func() { held = false }, nil
	}
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	other := restartManager(m)
	before := s.writes
	if err := other.Recover(); !errors.Is(err, ErrAlreadyRunning) || s.writes != before || !held {
		t.Fatal("another manager touched active ownership", err)
	}
	m.ownerAlive = func(journalOwner) (bool, error) { return true, nil }
	if err := m.Recover(); !errors.Is(err, ErrAlreadyRunning) || !held {
		t.Fatal("Recover released a live session's own lease", err)
	}
	if err := m.Restore(); err != nil || held {
		t.Fatal("owner cleanup did not release lease", err)
	}
}

func TestRestoreCallbacksAndResultReadsAreSerialized(t *testing.T) {
	m, _ := memoryManager(t)
	if err := m.Begin("127.0.0.1:18080", nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.Restore()
			_ = m.LastResult()
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIncompleteAppliedAndUnknownJSONValuesAreRejected(t *testing.T) {
	for _, mutation := range []string{"applied-extra-key", "applied-overflow", "null-original", "missing-exists", "null-had-key", "null-touched"} {
		t.Run(mutation, func(t *testing.T) {
			m, s := memoryManager(t)
			if err := m.Begin("127.0.0.1:18080", nil); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(m.snapPath())
			if err != nil {
				t.Fatal(err)
			}
			var object map[string]any
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			values := object["values"].(map[string]any)[regKeyPath].(map[string]any)
			applied := object["applied"].(map[string]any)
			switch mutation {
			case "applied-extra-key":
				applied[`Software\Unrelated`] = values
			case "applied-overflow":
				applied[regKeyPath].(map[string]any)["ProxyEnable"].(map[string]any)["integer"] = float64(1 << 40)
			case "null-original":
				values["ProxyServer"] = nil
			case "missing-exists":
				delete(values["ProxyServer"].(map[string]any), "exists")
			case "null-had-key":
				object["had_keys"].(map[string]any)[regKeyPath] = nil
			case "null-touched":
				object["touched"].(map[string]any)[regKeyPath] = nil
			}
			raw, _ = json.Marshal(object)
			if err := os.WriteFile(m.snapPath(), raw, 0600); err != nil {
				t.Fatal(err)
			}
			writes := s.writes
			if err := m.Restore(); err == nil || s.writes != writes {
				t.Fatal("incomplete/corrupt ownership evidence triggered writes", err)
			}
		})
	}
}

func FuzzPendingPolicyDecode(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"session":"00000000000000000000000000000000","bundles":{}}`))
	f.Add([]byte(`{"version":999}`))
	values := appliedSettings("127.0.0.1:18080", []string{"synthetic.invalid"})[chromiumPolicyPaths[0]]
	p := pendingPolicies{Version: 1, Session: "00000000000000000000000000000000", Bundles: map[string]settingsBundle{
		chromiumPolicyPaths[0]: {Values: values, Applied: values, HadKey: true},
	}}
	raw, _ := json.Marshal(p)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > journalSizeLimit {
			return
		}
		path := filepath.Join(t.TempDir(), "00000000000000000000000000000000.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		_, _ = readPending(path)
	})
}
