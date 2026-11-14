package netenv

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"opentunnel/internal/privatefile"
)

// One bounded record per session avoids overwriting earlier unresolved evidence.
// Records contain optional bundles only, never active WinINET ownership.
type pendingPolicies struct {
	Version int                       `json:"version"`
	Session string                    `json:"session"`
	Bundles map[string]settingsBundle `json:"bundles"`
}

func (m *Manager) pendingDir() string { return filepath.Join(m.Dir, "pending-policies") }
func (m *Manager) pendingPath(id string) string {
	return filepath.Join(m.pendingDir(), id+".json")
}

func (m *Manager) hasRecoveryState() bool {
	for _, path := range []string{m.snapPath(), m.pendingDir()} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func encodePending(p pendingPolicies) ([]byte, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(raw) > journalSizeLimit {
		return nil, errors.New("netenv: pending policies exceed recovery size limit")
	}
	return raw, nil
}

func readPending(path string) (pendingPolicies, error) {
	p := pendingPolicies{}
	raw, err := privatefile.Read(path, journalSizeLimit)
	if err != nil {
		return p, err
	}
	if err := requireJSONMembers(raw, "version", "session", "bundles"); err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if p.Version != 1 || !validJournalID(p.Session) || filepath.Base(path) != p.Session+".json" || len(p.Bundles) == 0 {
		return p, errors.New("netenv: invalid pending policy journal")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	var bundles map[string]json.RawMessage
	_ = json.Unmarshal(fields["bundles"], &bundles)
	for path, b := range p.Bundles {
		if !policyPath(path) {
			return p, errors.New("netenv: pending journal names a mandatory or unrelated key")
		}
		if err := requireJSONMembers(bundles[path], "values", "had_key"); err != nil {
			return p, err
		}
		var members map[string]json.RawMessage
		_ = json.Unmarshal(bundles[path], &members)
		if _, ok := members["applied"]; !ok {
			return p, errors.New("netenv: pending journal omits applied ownership")
		}
		if err := validateJSONValueMap(members["values"], path); err != nil {
			return p, err
		}
		if err := validateValueMap(path, b.Values); err != nil {
			return p, err
		}
		// Old pre-address journals cannot establish ownership; keep them for
		// explicit recovery rather than guessing which settings are ours.
		if b.Applied != nil {
			if err := validateJSONValueMap(members["applied"], path); err != nil {
				return p, err
			}
			if err := validateValueMap(path, b.Applied); err != nil {
				return p, err
			}
		} else if b.LegacyBypass {
			return p, errors.New("netenv: legacy pending bundle has no applied address")
		}
	}
	return p, nil
}

func (m *Manager) detachPolicies(s snapshot, force bool) error {
	p := pendingPolicies{Version: 1, Session: s.ID, Bundles: make(map[string]settingsBundle)}
	for _, path := range chromiumPolicyPaths {
		if _, captured := s.Values[path]; !captured || (!force && !s.Touched[path]) {
			continue
		}
		b := s.bundle(path)
		// RestoreFrom pinned current values before mutation. Reuse that exact
		// authorization; do not silently re-arm against newer competing values.
		p.Bundles[path] = b
	}
	if len(p.Bundles) == 0 {
		return nil
	}
	path := m.pendingPath(s.ID)
	if _, err := os.Lstat(path); err == nil {
		// Recovery may have crashed after detaching, before deleting the
		// active journal. Reuse the durable copy, never recreate completed
		// bundles or reset a resolved legacy bypass to "unknown".
		existing, err := readPending(path)
		if err != nil {
			return err
		}
		for bundlePath, b := range existing.Bundles {
			original, ok := p.Bundles[bundlePath]
			if !ok || b.HadKey != original.HadKey || !reflect.DeepEqual(b.Values, original.Values) {
				return errors.New("netenv: pending session collides with a different recovery journal")
			}
			if !force {
				// The only permitted difference is a durably resolved legacy
				// bypass. A collision must not substitute unrelated ownership.
				applied := cloneValues(b.Applied)
				if original.LegacyBypass && !b.LegacyBypass {
					applied[bypassName(bundlePath)] = original.Applied[bypassName(bundlePath)]
				} else if original.LegacyBypass != b.LegacyBypass {
					return errors.New("netenv: conflicting pending legacy ownership")
				}
				if !sameBundle(applied, original.Applied) {
					return errors.New("netenv: conflicting pending applied settings")
				}
			}
		}
		if force {
			// The explicit operator request may re-arm this session's pending
			// policies against the current values just captured above. This is
			// not a permanent force bit: later retries still check ownership.
			raw, err := encodePending(p)
			if err != nil {
				return err
			}
			return writeRecoveryState(path, raw)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := encodePending(p)
	if err != nil {
		return err
	}
	return newRecoveryState(path, raw)
}

func (m *Manager) pendingFiles() ([]string, error) {
	info, err := os.Lstat(m.pendingDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("netenv: pending policy directory is not a regular directory")
	}
	if err := privatefile.EnsureDir(m.pendingDir()); err != nil {
		return nil, err
	}
	f, err := os.Open(m.pendingDir())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Normal records name at most five bundles, and skipped pending bundles
	// cannot be journaled by another session. Bound hostile same-user state.
	entries, err := f.ReadDir(65)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 64 {
		return nil, errors.New("netenv: too many pending policy records; manual review required")
	}
	var paths []string
	for _, entry := range entries {
		if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			paths = append(paths, filepath.Join(m.pendingDir(), entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// retryPendingPolicies is called only while holding the settings lease and
// never while an active session is being served. Failed reads/conflicts/writes
// retain exact evidence and block ONLY the affected optional bundles in Begin.
func (m *Manager) retryPendingPolicies() map[string]bool {
	blocked := make(map[string]bool)
	blockAll := func(err error) {
		m.warn("pending-policies", "cleanup record unreadable; browser-policy apply skipped", err)
		for _, path := range chromiumPolicyPaths {
			blocked[path] = true
		}
	}
	files, err := m.pendingFiles()
	if err != nil {
		blockAll(err)
	} else {
		// Validate every record before writing any bundle. A corrupt older
		// record or duplicate claim makes policy ownership ambiguous; preserve
		// all evidence rather than letting another record overwrite it.
		records := make(map[string]pendingPolicies)
		counts := make(map[string]int)
		invalid := false
		for _, file := range files {
			p, err := readPending(file)
			if err != nil {
				blockAll(err)
				invalid = true
				continue
			}
			records[file] = p
			for path := range p.Bundles {
				counts[path]++
			}
		}
		for _, file := range files {
			p, exists := records[file]
			if invalid || !exists {
				continue
			}
			for _, path := range chromiumPolicyPaths {
				b, exists := p.Bundles[path]
				if !exists {
					continue
				}
				if counts[path] > 1 {
					blocked[path] = true
					m.warn(path, "multiple cleanup records claim this bundle; manual review required", ErrSettingsConflict)
					continue
				}
				if err := m.restoreBundle(path, &b, func(b settingsBundle) error {
					p.Bundles[path] = b
					raw, err := encodePending(p)
					if err != nil {
						return err
					}
					old, err := privatefile.Read(file, journalSizeLimit)
					if err != nil {
						return err
					}
					if bytes.Equal(old, raw) {
						return nil
					}
					return writeRecoveryState(file, raw)
				}); err != nil {
					blocked[path] = true
					m.warn(path, "cleanup pending; recovery evidence retained", err)
					continue
				}
				delete(p.Bundles, path)
				var err error
				if len(p.Bundles) == 0 {
					err = removeRecoveryState(file)
				} else {
					var raw []byte
					raw, err = encodePending(p)
					if err == nil {
						err = writeRecoveryState(file, raw)
					}
				}
				if err != nil {
					blocked[path] = true
					m.warn(path, "cleanup completed but recovery record update failed", err)
					// Do not overwrite a stale on-disk record with subsequent
					// changes. Every remaining bundle remains retryable.
					for remaining := range p.Bundles {
						blocked[remaining] = true
					}
					break
				}
			}
		}
	}
	for _, path := range chromiumPolicyPaths {
		if blocked[path] {
			m.result.PendingPolicies = appendUnique(m.result.PendingPolicies, path)
		}
	}
	if m.notify != nil && len(files) != 0 {
		m.notify()
	}
	return blocked
}

func (m *Manager) PendingPolicyCleanup() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	files, err := m.pendingFiles()
	return err != nil || len(files) != 0
}
