// Package netenv journals and restores user-level proxy settings. Restoration
// is best effort during shutdown, backed by retryable crash-recovery state;
// it is not a guarantee against OS shutdown, denied writes or disk failure.
package netenv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/privatefile"
)

const regKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var chromiumPolicyPaths = []string{`Software\Policies\Google\Chrome`, `Software\Policies\Microsoft\Edge`, `Software\Policies\BraveSoftware\Brave`, `Software\Policies\Vivaldi`, `Software\Policies\Chromium`}

const (
	polMode   = "ProxyMode"
	polServer = "ProxyServer"
	polBypass = "ProxyBypassList"
)

var ErrAlreadyRunning = errors.New("netenv: another client owns the settings lease")
var ErrSettingsConflict = errors.New("netenv: settings changed by another application; journal retained")

type registryValue struct {
	Exists  bool     `json:"exists"`
	Kind    uint32   `json:"kind,omitempty"`
	Text    string   `json:"text,omitempty"`
	Integer uint64   `json:"integer,omitempty"`
	Bytes   []byte   `json:"bytes,omitempty"`
	Strings []string `json:"strings,omitempty"`
}
type settingsStore interface {
	KeyExists(path string) (bool, error)
	Read(path, name string) (registryValue, error)
	Write(path, name string, value registryValue) error
	DeleteEmptyKey(path string) error
}
type journalOwner struct {
	PID     int    `json:"pid"`
	Image   string `json:"image,omitempty"`
	Created uint64 `json:"created,omitempty"`
}
type stringVal struct {
	Exists bool   `json:"exists"`
	Data   string `json:"data,omitempty"`
}
type policySnap struct {
	Mode   stringVal `json:"mode"`
	Server stringVal `json:"server"`
	Bypass stringVal `json:"bypass"`
	HadKey bool      `json:"had_key"`
}
type snapshot struct {
	Version int                                 `json:"version,omitempty"`
	Owner   journalOwner                        `json:"owner,omitempty"`
	Values  map[string]map[string]registryValue `json:"values,omitempty"`
	Applied map[string]map[string]registryValue `json:"applied,omitempty"`
	HadKeys map[string]bool                     `json:"had_keys,omitempty"`
	// Preserve the old journal format for recovery of existing clients.
	ProxyEnable      uint32                `json:"proxy_enable"`
	ProxyServer      stringVal             `json:"proxy_server"`
	ProxyOverride    stringVal             `json:"proxy_override"`
	AutoConfigURL    stringVal             `json:"autoconfig_url"`
	Policies         map[string]policySnap `json:"policies,omitempty"`
	OtuAppliedServer string                `json:"otu_applied_server,omitempty"`
}

type Manager struct {
	Dir          string
	mu           sync.Mutex
	store        settingsStore
	notify       func()
	owner        func() (journalOwner, error)
	ownerAlive   func(journalOwner) (bool, error)
	leaseFactory func(string) (func(), error)
	leaseRelease func()
	backup       func([]byte)
}

func (m *Manager) snapPath() string { return filepath.Join(m.Dir, "snapshot.json") }
func (m *Manager) lockPath() string { return filepath.Join(m.Dir, "lock.pid") }
func settingsNames(path string) []string {
	if path == regKeyPath {
		return []string{"ProxyServer", "ProxyOverride", "AutoConfigURL", "ProxyEnable"}
	}
	return []string{polServer, polBypass, polMode}
}
func settingsPaths() []string { return append([]string{regKeyPath}, chromiumPolicyPaths...) }

func (m *Manager) acquireLease() error {
	if m.leaseRelease != nil {
		return nil
	}
	if m.leaseFactory == nil {
		m.leaseRelease = func() {}
		return nil
	}
	release, err := m.leaseFactory(m.Dir)
	if err != nil {
		return err
	}
	m.leaseRelease = release
	return nil
}
func (m *Manager) releaseLease() {
	if m.leaseRelease != nil {
		m.leaseRelease()
		m.leaseRelease = nil
	}
}

func (m *Manager) Begin(proxyAddr string, bypass []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		return errors.New("netenv: --auto-proxy is only supported on Windows")
	}
	if err := privatefile.EnsureDir(m.Dir); err != nil {
		return err
	}
	hadLease := m.leaseRelease != nil
	if err := m.acquireLease(); err != nil {
		return err
	}
	if _, err := os.Stat(m.snapPath()); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			m.releaseLease()
			return err
		}
		if !hadLease {
			m.releaseLease()
		}
		return errors.New("netenv: existing journal must be recovered before applying settings")
	}
	s := snapshot{Version: 2, Values: make(map[string]map[string]registryValue), HadKeys: make(map[string]bool), OtuAppliedServer: proxyAddr}
	if m.owner != nil {
		var err error
		s.Owner, err = m.owner()
		if err != nil {
			m.releaseLease()
			return err
		}
	}
	for _, path := range settingsPaths() {
		exists, err := m.store.KeyExists(path)
		if err != nil {
			m.releaseLease()
			return fmt.Errorf("netenv: snapshot key: %w", err)
		}
		s.HadKeys[path] = exists
		s.Values[path] = make(map[string]registryValue)
		for _, name := range settingsNames(path) {
			v, err := m.store.Read(path, name)
			if err != nil {
				m.releaseLease()
				return fmt.Errorf("netenv: snapshot %s: %w", name, err)
			}
			s.Values[path][name] = v
		}
	}
	s.Applied = appliedSettings(proxyAddr, bypass)
	s.fillLegacy()
	raw, err := json.Marshal(s)
	if err != nil {
		m.releaseLease()
		return err
	}
	if len(raw) > 256<<10 {
		m.releaseLease()
		return errors.New("netenv: settings snapshot exceeds recovery size limit; nothing changed")
	}
	if err := writeJournal(m.snapPath(), raw); err != nil {
		m.releaseLease()
		return fmt.Errorf("netenv: journal: %w", err)
	}
	if err := os.WriteFile(m.lockPath(), []byte(strconv.Itoa(s.Owner.PID)), 0o600); err != nil {
		return errors.Join(err, m.restoreSnapshot(s, false))
	}
	if m.backup != nil {
		m.backup(raw)
	}
	// Detect a competing proxy change between snapshot and apply before
	// mutating anything. The lease serializes opentunnel, not other software.
	for _, path := range settingsPaths() {
		for _, name := range settingsNames(path) {
			current, err := m.store.Read(path, name)
			if err != nil {
				return err
			}
			if !sameValue(current, s.Values[path][name]) {
				return ErrSettingsConflict
			}
		}
	}
	for _, path := range settingsPaths() {
		for _, name := range settingsNames(path) {
			current, err := m.store.Read(path, name)
			if err != nil {
				return errors.Join(err, m.restoreSnapshot(s, false))
			}
			if !sameValue(current, s.Values[path][name]) {
				return errors.Join(ErrSettingsConflict, m.restoreSnapshot(s, false))
			}
			if err := m.store.Write(path, name, s.Applied[path][name]); err != nil {
				return errors.Join(fmt.Errorf("netenv: apply %s: %w", name, err), m.restoreSnapshot(s, false))
			}
			if actual, err := m.store.Read(path, name); err != nil || !sameValue(actual, s.Applied[path][name]) {
				return errors.Join(errors.New("netenv: settings application did not persist"), err, m.restoreSnapshot(s, false))
			}
		}
	}
	if m.notify != nil {
		m.notify()
	}
	return nil
}

func appliedSettings(proxyAddr string, bypass []string) map[string]map[string]registryValue {
	str := func(s string) registryValue { return registryValue{Exists: true, Kind: 1, Text: s} }
	override := "localhost;127.0.0.1;<local>"
	for _, b := range bypass {
		if b = strings.TrimSpace(b); b != "" {
			override += ";" + b
		}
	}
	values := map[string]map[string]registryValue{regKeyPath: {"ProxyEnable": {Exists: true, Kind: 4, Integer: 1}, "ProxyServer": str(proxyAddr), "ProxyOverride": str(override), "AutoConfigURL": {}}}
	for _, path := range chromiumPolicyPaths {
		values[path] = map[string]registryValue{polMode: str("fixed_servers"), polServer: str(proxyAddr), polBypass: str(strings.ReplaceAll(override, ";", ","))}
	}
	return values
}

func (s *snapshot) fillLegacy() {
	legacy := func(v registryValue) stringVal { return stringVal{Exists: v.Exists, Data: v.Text} }
	v := s.Values[regKeyPath]
	s.ProxyEnable = uint32(v["ProxyEnable"].Integer)
	s.ProxyServer = legacy(v["ProxyServer"])
	s.ProxyOverride = legacy(v["ProxyOverride"])
	s.AutoConfigURL = legacy(v["AutoConfigURL"])
	s.Policies = make(map[string]policySnap)
	for _, path := range chromiumPolicyPaths {
		v := s.Values[path]
		s.Policies[path] = policySnap{Mode: legacy(v[polMode]), Server: legacy(v[polServer]), Bypass: legacy(v[polBypass]), HadKey: s.HadKeys[path]}
	}
}

func readSnapshot(path string) (snapshot, error) {
	s := snapshot{}
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 256<<10+1))
	if err != nil {
		return s, err
	}
	if len(raw) > 256<<10 {
		return s, errors.New("netenv: journal too large")
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("netenv: corrupt journal retained: %w", err)
	}
	if s.Version != 0 && s.Version != 2 {
		return s, errors.New("netenv: unsupported journal version")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return s, err
	}
	if s.Version == 0 {
		for _, name := range []string{"proxy_enable", "proxy_server", "proxy_override", "autoconfig_url"} {
			if _, ok := fields[name]; !ok {
				return s, errors.New("netenv: incomplete legacy journal")
			}
		}
	} else {
		if s.Owner.PID <= 0 {
			return s, errors.New("netenv: settings journal has no valid owner")
		}
		for _, path := range settingsPaths() {
			if _, ok := s.HadKeys[path]; !ok {
				return s, errors.New("netenv: incomplete key-existence journal")
			}
			for _, name := range settingsNames(path) {
				if _, ok := s.Values[path][name]; !ok {
					return s, errors.New("netenv: incomplete settings journal")
				}
				if _, ok := s.Applied[path][name]; !ok {
					return s, errors.New("netenv: incomplete applied-settings journal")
				}
			}
		}
	}
	if s.Values == nil {
		str := func(v stringVal) registryValue { return registryValue{Exists: v.Exists, Kind: 1, Text: v.Data} }
		s.Values = map[string]map[string]registryValue{regKeyPath: {"ProxyEnable": {Exists: true, Kind: 4, Integer: uint64(s.ProxyEnable)}, "ProxyServer": str(s.ProxyServer), "ProxyOverride": str(s.ProxyOverride), "AutoConfigURL": str(s.AutoConfigURL)}}
		s.HadKeys = map[string]bool{regKeyPath: true}
		for path, v := range s.Policies {
			s.Values[path] = map[string]registryValue{polMode: str(v.Mode), polServer: str(v.Server), polBypass: str(v.Bypass)}
			s.HadKeys[path] = v.HadKey
		}
		if s.OtuAppliedServer != "" {
			s.Applied = appliedSettings(s.OtuAppliedServer, nil)
		}
	}
	allowed := map[string]bool{}
	for _, path := range settingsPaths() {
		allowed[path] = true
	}
	for path, values := range s.Values {
		if !allowed[path] {
			return s, errors.New("netenv: journal names an unrelated registry key")
		}
		names := map[string]bool{}
		for _, name := range settingsNames(path) {
			names[name] = true
		}
		for name, v := range values {
			if v.Kind == 4 && v.Integer > 1<<32-1 {
				return s, errors.New("netenv: DWORD restoration would overflow")
			}
			if !names[name] || (v.Exists && v.Kind != 1 && v.Kind != 2 && v.Kind != 3 && v.Kind != 4 && v.Kind != 7 && v.Kind != 11) {
				return s, errors.New("netenv: invalid journal value")
			}
		}
	}
	return s, nil
}

func writeJournal(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := privatefile.EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".network-journal-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := privatefile.Protect(tmp); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	// The exclusive settings lease prevents concurrent writers. Do not
	// overwrite even an orphaned journal; it may be the only recovery copy.
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("netenv: journal already exists")
	}
	return os.Rename(tmp, path)
}

func (m *Manager) Recover() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		return nil
	}
	if _, err := os.Stat(m.snapPath()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := m.acquireLease(); err != nil {
		return err
	}
	defer m.releaseLease()
	s, err := readSnapshot(m.snapPath())
	if err != nil {
		return err
	}
	if s.Owner.PID == 0 {
		if raw, err := os.ReadFile(m.lockPath()); err == nil {
			s.Owner.PID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		}
	}
	if s.Owner.PID > 0 && m.ownerAlive != nil {
		alive, err := m.ownerAlive(s.Owner)
		if err != nil {
			return err
		}
		if alive {
			return ErrAlreadyRunning
		}
	}
	return m.restoreSnapshot(s, false)
}

func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		return nil
	}
	s, err := readSnapshot(m.snapPath())
	if errors.Is(err, os.ErrNotExist) {
		m.releaseLease()
		return nil
	}
	if err != nil {
		return err
	}
	hadLease := m.leaseRelease != nil
	if err := m.acquireLease(); err != nil {
		return err
	}
	if !hadLease {
		if err := m.checkOwner(s); err != nil {
			m.releaseLease()
			return err
		}
	}
	return m.restoreSnapshot(s, false)
}

func (m *Manager) RestoreFrom(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		return nil
	}
	s, err := readSnapshot(path)
	if err != nil {
		return err
	}
	hadLease := m.leaseRelease != nil
	if err := m.acquireLease(); err != nil {
		return err
	}
	if !hadLease {
		if current, err := readSnapshot(m.snapPath()); err == nil {
			if err := m.checkOwner(current); err != nil {
				m.releaseLease()
				return err
			}
		}
	}
	return m.restoreSnapshot(s, true)
}

func (m *Manager) checkOwner(s snapshot) error {
	if s.Owner.PID == 0 {
		if raw, err := os.ReadFile(m.lockPath()); err == nil {
			s.Owner.PID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		}
	}
	if s.Owner.PID > 0 && m.ownerAlive != nil {
		alive, err := m.ownerAlive(s.Owner)
		if err != nil {
			return err
		}
		if alive {
			return ErrAlreadyRunning
		}
	}
	return nil
}

func sameValue(a, b registryValue) bool {
	if !a.Exists && !b.Exists {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func (m *Manager) restoreSnapshot(s snapshot, force bool) error {
	var failures []error
	for _, path := range settingsPaths() {
		values, captured := s.Values[path]
		if !captured {
			continue
		}
		// Settings within one registry key form a logical bundle. If a user
		// changed the server, do not restore ProxyEnable and silently disable
		// their replacement proxy while retaining only its address.
		conflict := false
		for _, name := range settingsNames(path) {
			original, captured := values[name]
			if !captured {
				continue
			}
			current, err := m.store.Read(path, name)
			if err != nil {
				failures = append(failures, err)
				conflict = true
				continue
			}
			if applied, ok := s.Applied[path][name]; !force && s.Applied != nil && !sameValue(current, original) && (!ok || !sameValue(current, applied)) {
				conflict = true
				failures = append(failures, ErrSettingsConflict)
			}
		}
		if conflict {
			continue
		}
		for _, name := range settingsNames(path) {
			original, captured := values[name]
			if !captured {
				continue
			}
			current, err := m.store.Read(path, name)
			if err != nil {
				failures = append(failures, fmt.Errorf("netenv: read %s: %w", name, err))
				continue
			}
			if sameValue(current, original) {
				continue
			}
			if applied, ok := s.Applied[path][name]; !force && s.Applied != nil && (!ok || !sameValue(current, applied)) {
				failures = append(failures, ErrSettingsConflict)
				continue
			}
			if err := m.store.Write(path, name, original); err != nil {
				failures = append(failures, fmt.Errorf("netenv: restore %s: %w", name, err))
			}
			if actual, err := m.store.Read(path, name); err != nil || !sameValue(actual, original) {
				failures = append(failures, errors.New("netenv: restore was not durable; journal retained"), err)
			}
		}
		if !s.HadKeys[path] && path != regKeyPath {
			if err := m.store.DeleteEmptyKey(path); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if m.notify != nil {
		m.notify()
	}
	if err := errors.Join(failures...); err != nil {
		return err
	} // preserve journal and lease for retry
	if err := os.Remove(m.snapPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(m.lockPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.releaseLease()
	_ = os.Remove(filepath.Join(m.Dir, "network-settings.lease"))
	return nil
}

func backupSnapshot(raw []byte) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Join(filepath.Dir(exe), "settings-backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	name := "network-settings-" + time.Now().Format("20060102-150405") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		return
	}
	entries, _ := filepath.Glob(filepath.Join(dir, "network-settings-*.json"))
	sort.Strings(entries)
	for len(entries) > 3 {
		_ = os.Remove(entries[0])
		entries = entries[1:]
	}
	bat := "@echo off\r\n\"%~dp0..\\" + filepath.Base(exe) + "\" --restore-from \"%~dp0" + name + "\"\r\nif errorlevel 1 (echo Restore failed - keep the backup and retry.) else (echo Network settings restored.)\r\npause\r\n"
	_ = os.WriteFile(filepath.Join(dir, "restore-network.bat"), []byte(bat), 0o755)
}
