package netenv

import (
	"errors"
	"fmt"
)

// PolicyWarning reports degraded optional handling without turning it into a
// mandatory WinINET failure. It deliberately contains no registry value data.
type PolicyWarning struct {
	Path      string
	Operation string
	Err       error
}

func (w PolicyWarning) Error() string {
	return fmt.Sprintf("%s: %s: %v", w.Path, w.Operation, w.Err)
}

// Result is the outcome of the last Begin, Recover, Restore or RestoreFrom.
// A nil method error means mandatory work completed, not that every browser
// policy was applied or restored. Pending cleanup is durable and nonfatal.
type Result struct {
	AppliedPolicies []string
	SkippedPolicies []string
	PendingPolicies []string
	Warnings        []PolicyWarning
}

func (m *Manager) LastResult() Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.result
	r.AppliedPolicies = append([]string(nil), r.AppliedPolicies...)
	r.SkippedPolicies = append([]string(nil), r.SkippedPolicies...)
	r.PendingPolicies = append([]string(nil), r.PendingPolicies...)
	r.Warnings = append([]PolicyWarning(nil), r.Warnings...)
	return r
}

func (m *Manager) warn(path, operation string, err error) {
	m.result.Warnings = append(m.result.Warnings, PolicyWarning{Path: path, Operation: operation, Err: err})
}

func appendUnique(paths []string, path string) []string {
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

type settingsBundle struct {
	Values       map[string]registryValue `json:"values"`
	Applied      map[string]registryValue `json:"applied"`
	HadKey       bool                     `json:"had_key"`
	LegacyBypass bool                     `json:"legacy_bypass,omitempty"`
}

func (s snapshot) bundle(path string) settingsBundle {
	return settingsBundle{Values: s.Values[path], Applied: s.Applied[path], HadKey: s.HadKeys[path], LegacyBypass: s.LegacyBypass[path]}
}

func (s *snapshot) setBundle(path string, b settingsBundle) {
	s.Values[path], s.Applied[path], s.HadKeys[path] = b.Values, b.Applied, b.HadKey
	if s.LegacyBypass == nil {
		s.LegacyBypass = make(map[string]bool)
	}
	if b.LegacyBypass {
		s.LegacyBypass[path] = true
	} else {
		delete(s.LegacyBypass, path)
	}
}

func cloneValues(values map[string]registryValue) map[string]registryValue {
	out := make(map[string]registryValue, len(values))
	for name, v := range values {
		out[name] = v
	}
	return out
}

func sameBundle(a, b map[string]registryValue) bool {
	if len(a) != len(b) {
		return false
	}
	for name, v := range a {
		other, ok := b[name]
		if !ok || !sameValue(v, other) {
			return false
		}
	}
	return true
}

func (m *Manager) readBundle(path string) (map[string]registryValue, error) {
	values := make(map[string]registryValue)
	for _, name := range settingsNames(path) {
		v, err := m.store.Read(path, name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if err := validateRegistryValue(v); err != nil {
			return nil, err
		}
		values[name] = v
	}
	return values, nil
}

func (m *Manager) captureBundle(path string) (bool, map[string]registryValue, error) {
	exists, err := m.store.KeyExists(path)
	if err != nil {
		return false, nil, fmt.Errorf("read key existence: %w", err)
	}
	values, err := m.readBundle(path)
	if err != nil {
		return false, nil, err
	}
	if !exists {
		for _, v := range values {
			if v.Exists {
				return false, nil, ErrSettingsConflict
			}
		}
	}
	return exists, values, nil
}

// applyBundle checks all related values before the first write and again before
// every subsequent write. An optional error stops the bundle, not the client.
// arm persists ownership before mutation, including writes with uncertain error
// results. The OS has no compare-and-swap API for these registry bundles, so
// these checks cannot eliminate a competing write inside the final syscall.
func (m *Manager) applyBundle(path string, b settingsBundle, arm func() error) error {
	expected := cloneValues(b.Values)
	armed := false
	for _, name := range settingsNames(path) {
		current, err := m.readBundle(path)
		if err != nil {
			return err
		}
		if !sameBundle(current, expected) {
			return ErrSettingsConflict
		}
		if sameValue(current[name], b.Applied[name]) {
			continue
		}
		if !armed {
			if err := arm(); err != nil {
				return fmt.Errorf("journal ownership before apply: %w", err)
			}
			armed = true
			// Journaling can take long enough for another application to
			// change the bundle. Recheck after arming the first mutation.
			current, err = m.readBundle(path)
			if err != nil {
				return err
			}
			if !sameBundle(current, expected) {
				return ErrSettingsConflict
			}
		}
		if err := m.store.Write(path, name, b.Applied[name]); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if actual, err := m.store.Read(path, name); err != nil || !sameValue(actual, b.Applied[name]) {
			return errors.Join(errors.New("netenv: settings application did not persist"), err)
		}
		expected[name] = b.Applied[name]
	}
	current, err := m.readBundle(path)
	if err != nil {
		return err
	}
	if !sameBundle(current, expected) {
		return ErrSettingsConflict
	}
	return nil
}

func bypassName(path string) string {
	if path == regKeyPath {
		return "ProxyOverride"
	}
	return polBypass
}

// A missing legacy applied bypass is not permission to overwrite arbitrary
// bypasses. Require the exact journal-owned address AND active proxy mode.
func ownsAppliedBundle(path string, b settingsBundle, current map[string]registryValue) bool {
	serverName, modeName := polServer, polMode
	if path == regKeyPath {
		serverName, modeName = "ProxyServer", "ProxyEnable"
	}
	server, ok := b.Applied[serverName]
	return ok && server.Exists && server.Kind == 1 && server.Text != "" &&
		sameValue(current[serverName], server) && sameValue(current[modeName], b.Applied[modeName])
}

func restoreAllowed(path string, b settingsBundle, current map[string]registryValue) bool {
	for name, original := range b.Values {
		if sameValue(current[name], original) {
			continue
		}
		if b.LegacyBypass && name == bypassName(path) {
			// v1.1.5 wrote a REG_SZ bypass. A different type or missing value
			// is not an unknown config-specific applied bypass.
			if !current[name].Exists || current[name].Kind != 1 || !ownsAppliedBundle(path, b, current) {
				return false
			}
			continue
		}
		applied, ok := b.Applied[name]
		if !ok || !sameValue(current[name], applied) {
			return false
		}
	}
	return true
}

// restoreBundle accepts only original/applied values for the entire bundle.
// Resolving an unknown legacy bypass is persisted BEFORE any restoration; a
// partial restore therefore cannot lose ownership or broaden future retries.
func (m *Manager) restoreBundle(path string, b *settingsBundle, persist func(settingsBundle) error) error {
	current, err := m.readBundle(path)
	if err != nil {
		return err
	}
	if !restoreAllowed(path, *b, current) {
		return ErrSettingsConflict
	}
	name := bypassName(path)
	if b.LegacyBypass && !sameValue(current[name], b.Values[name]) && ownsAppliedBundle(path, *b, current) {
		resolved := *b
		resolved.Applied = cloneValues(b.Applied)
		resolved.Applied[name], resolved.LegacyBypass = current[name], false
		if persist == nil {
			return errors.New("netenv: legacy bypass must be journaled before restoration")
		}
		if err := persist(resolved); err != nil {
			return fmt.Errorf("journal resolved legacy bypass: %w", err)
		}
		*b = resolved
	}
	expected := cloneValues(current)
	var failures []error
	for _, name := range settingsNames(path) {
		current, err := m.readBundle(path)
		if err != nil {
			return errors.Join(errors.Join(failures...), err)
		}
		if !sameBundle(current, expected) {
			return errors.Join(errors.Join(failures...), ErrSettingsConflict)
		}
		original := b.Values[name]
		if sameValue(current[name], original) {
			continue
		}
		if writeErr := m.store.Write(path, name, original); writeErr != nil {
			failures = append(failures, fmt.Errorf("restore %s: %w", name, writeErr))
			// A denied value need not prevent restoration of other known
			// values (especially disabling our dead WinINET proxy). Continue
			// only if readback proves the complete bundle is still exactly the
			// expected state or this one value reached its original state.
			actual, err := m.readBundle(path)
			if err != nil {
				return errors.Join(errors.Join(failures...), err)
			}
			if !sameBundle(actual, expected) {
				updated := cloneValues(expected)
				updated[name] = original
				if !sameBundle(actual, updated) {
					return errors.Join(errors.Join(failures...), ErrSettingsConflict)
				}
				expected = updated
			}
			continue
		}
		if actual, err := m.store.Read(path, name); err != nil || !sameValue(actual, original) {
			return errors.Join(errors.Join(failures...), errors.New("netenv: restore was not durable; journal retained"), err)
		}
		expected[name] = original
	}
	current, err = m.readBundle(path)
	if err != nil {
		return errors.Join(errors.Join(failures...), err)
	}
	if err := errors.Join(failures...); err != nil {
		return err // even a partial known restore must retain retry evidence
	}
	if !sameBundle(current, b.Values) {
		return ErrSettingsConflict
	}
	if !b.HadKey && policyPath(path) {
		exists, err := m.store.KeyExists(path)
		if err != nil {
			return err
		}
		if exists {
			if err := m.store.DeleteEmptyKey(path); err != nil {
				return fmt.Errorf("remove created empty policy key: %w", err)
			}
		}
	}
	return nil
}
