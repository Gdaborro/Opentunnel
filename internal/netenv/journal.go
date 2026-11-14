// Package netenv journals and restores user-level proxy settings. Restoration
// is best effort during shutdown, backed by retryable crash-recovery state;
// it is not a guarantee against OS shutdown, denied writes or disk failure.
package netenv

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	ID      string                              `json:"id,omitempty"`
	Owner   journalOwner                        `json:"owner,omitempty"`
	Values  map[string]map[string]registryValue `json:"values,omitempty"`
	Applied map[string]map[string]registryValue `json:"applied,omitempty"`
	HadKeys map[string]bool                     `json:"had_keys,omitempty"`
	Touched map[string]bool                     `json:"touched,omitempty"`
	// Only migrated journals may have an owner without a PID or an unknown
	// applied bypass. Resolve that bypass durably before restoring its bundle.
	RecoveryOnly bool            `json:"recovery_only,omitempty"`
	LegacyBypass map[string]bool `json:"legacy_bypass,omitempty"`
	importRaw    []byte
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
	result       Result
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

// policyPath reports whether path is an optional Chromium policy key.
// Managed machines commonly make HKCU\Software\Policies read-only; v1.1.5
// applied these keys best-effort, so a denied policy write must never take
// down the client. The WinINET settings in regKeyPath stay mandatory.
func policyPath(path string) bool {
	for _, allowed := range chromiumPolicyPaths {
		if path == allowed {
			return true
		}
	}
	return false
}

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
	m.result = Result{}
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
	// Retry detached cleanup first. Unresolved or unreadable records block only
	// their policy bundles, not the mandatory WinINET settings. Never capture a
	// previous session's applied policy as the next session's original value.
	blocked := m.retryPendingPolicies()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		m.releaseLease()
		return err
	}
	s := snapshot{Version: 3, ID: hex.EncodeToString(id), Values: make(map[string]map[string]registryValue),
		Applied: make(map[string]map[string]registryValue), HadKeys: make(map[string]bool), Touched: make(map[string]bool), OtuAppliedServer: proxyAddr}
	if m.owner != nil {
		var err error
		s.Owner, err = m.owner()
		if err != nil {
			m.releaseLease()
			return err
		}
	}
	if s.Owner.PID <= 0 {
		m.releaseLease()
		return errors.New("netenv: could not identify settings journal owner")
	}
	intended := appliedSettings(proxyAddr, bypass)
	for _, path := range settingsPaths() {
		if blocked[path] {
			m.result.SkippedPolicies = append(m.result.SkippedPolicies, path)
			continue
		}
		exists, values, err := m.captureBundle(path)
		if err != nil {
			if !policyPath(path) {
				m.releaseLease()
				return fmt.Errorf("netenv: snapshot: %w", err)
			}
			m.warn(path, "snapshot skipped; original values are unknown", err)
			m.result.SkippedPolicies = append(m.result.SkippedPolicies, path)
			continue
		}
		s.HadKeys[path], s.Values[path], s.Applied[path], s.Touched[path] = exists, values, intended[path], false
	}
	s.fillLegacy()
	raw, err := json.Marshal(s)
	if err != nil {
		m.releaseLease()
		return err
	}
	if len(raw) > journalSizeLimit {
		m.releaseLease()
		return errors.New("netenv: settings snapshot exceeds recovery size limit; nothing changed")
	}
	if err := writeJournal(m.snapPath(), raw); err != nil {
		m.releaseLease()
		return fmt.Errorf("netenv: journal: %w", err)
	}
	if err := privatefile.Write(m.lockPath(), []byte(strconv.Itoa(s.Owner.PID))); err != nil {
		return errors.Join(err, m.restoreSnapshot(s, false))
	}
	if m.backup != nil {
		m.backup(raw)
	}
	for _, path := range settingsPaths() {
		if _, captured := s.Values[path]; !captured {
			continue
		}
		err := m.applyBundle(path, s.bundle(path), func() error {
			s.Touched[path] = true
			if err := m.saveSnapshot(s); err != nil {
				s.Touched[path] = false
				return err
			}
			return nil
		})
		if err == nil {
			if policyPath(path) {
				m.result.AppliedPolicies = append(m.result.AppliedPolicies, path)
			}
			continue
		}
		if !policyPath(path) {
			return errors.Join(err, m.restoreSnapshot(s, false))
		}
		m.warn(path, "apply skipped", err)
		m.result.SkippedPolicies = append(m.result.SkippedPolicies, path)
		if s.Touched[path] {
			// A failed write/readback can have changed part of the bundle.
			// Roll back only known values, with the same conflict checks used
			// for crash recovery. Failed rollback remains journal-owned.
			b := s.bundle(path)
			if err := m.restoreBundle(path, &b, nil); err != nil {
				m.warn(path, "partial apply cleanup pending", err)
				m.result.PendingPolicies = appendUnique(m.result.PendingPolicies, path)
				continue
			}
			s.Touched[path] = false
			if err := m.saveSnapshot(s); err != nil {
				s.Touched[path] = true // the durable journal still owns it
				m.warn(path, "rollback completed but journal update failed", err)
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
		v, captured := s.Values[path]
		if !captured {
			continue
		}
		s.Policies[path] = policySnap{Mode: legacy(v[polMode]), Server: legacy(v[polServer]), Bypass: legacy(v[polBypass]), HadKey: s.HadKeys[path]}
	}
}

func writeJournal(path string, raw []byte) error {
	// No-replace publication preserves even an orphaned recovery journal.
	return newRecoveryState(path, raw)
}

func (m *Manager) saveSnapshot(s snapshot) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(raw) > journalSizeLimit {
		return errors.New("netenv: settings journal exceeds recovery size limit")
	}
	return writeRecoveryState(m.snapPath(), raw)
}

func (m *Manager) Recover() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.result = Result{}
	if m.store == nil {
		return nil
	}
	// Even without an active journal there may be detached policy cleanup.
	// Do not touch either kind of state while another client owns the lease.
	if !m.hasRecoveryState() {
		return nil
	}
	hadLease := m.leaseRelease != nil
	if err := m.acquireLease(); err != nil {
		return err
	}
	// A live session calling Recover must not release its own lease on the
	// ErrAlreadyRunning path. Other managers release their temporary lease.
	defer func() {
		if !hadLease {
			m.releaseLease()
		}
	}()
	s, err := readSnapshot(m.snapPath())
	if errors.Is(err, os.ErrNotExist) {
		m.retryPendingPolicies()
		return nil
	}
	if err != nil {
		return err
	}
	if err := m.checkOwner(s); err != nil {
		return err
	}
	return m.restoreSnapshot(s, false)
}

func (m *Manager) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.result = Result{}
	if m.store == nil {
		return nil
	}
	hadLease := m.leaseRelease != nil
	if !hadLease && !m.hasRecoveryState() {
		return nil
	}
	if err := m.acquireLease(); err != nil {
		return err
	}
	s, err := readSnapshot(m.snapPath())
	if errors.Is(err, os.ErrNotExist) {
		defer m.releaseLease()
		m.retryPendingPolicies()
		return nil
	}
	if err != nil {
		if !hadLease {
			m.releaseLease()
		}
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
	m.result = Result{}
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
		if err := m.checkOwner(s); err != nil {
			m.releaseLease()
			return err
		}
	}
	if current, err := readSnapshot(m.snapPath()); err == nil {
		if !hadLease {
			if err := m.checkOwner(current); err != nil {
				m.releaseLease()
				return err
			}
		}
		if current.ID != s.ID {
			if !hadLease {
				m.releaseLease()
			}
			return errors.New("netenv: active journal belongs to a different session; recover it before restoring this backup")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		if !hadLease {
			m.releaseLease()
		}
		return err // never discard an unreadable active journal
	}
	// Capture the mandatory bundle before installing backup state as the
	// active journal. A read failure must not overwrite another retry boundary
	// or turn operator force into an unjournaled write.
	mandatoryCurrent, err := m.readBundle(regKeyPath)
	if err != nil {
		if !hadLease {
			m.releaseLease()
		}
		return err
	}
	if err := m.upgradeSnapshot(&s); err != nil {
		if !hadLease {
			m.releaseLease()
		}
		return err
	}
	if s.Applied == nil {
		s.Applied = make(map[string]map[string]registryValue)
	}
	if s.LegacyBypass == nil {
		s.LegacyBypass = make(map[string]bool)
	}
	// An explicit backup restore still needs an active write-ahead journal.
	// Pin the CURRENT bundle values so a crash or partial force restoration
	// can be retried normally without a permanent permission to force later
	// administrator changes. The source backup itself is never modified.
	for _, bundlePath := range settingsPaths() {
		if _, captured := s.Values[bundlePath]; !captured {
			continue
		}
		current := mandatoryCurrent
		var err error
		if bundlePath != regKeyPath {
			current, err = m.readBundle(bundlePath)
		}
		if err != nil {
			if !policyPath(bundlePath) {
				if !hadLease {
					m.releaseLease()
				}
				return err
			}
			m.warn(bundlePath, "force restore could not capture current policy; normal conflict checks retained", err)
		} else {
			s.Applied[bundlePath] = current
			delete(s.LegacyBypass, bundlePath)
		}
		s.Touched[bundlePath] = true
	}
	if err := m.saveSnapshot(s); err != nil {
		if !hadLease {
			m.releaseLease()
		}
		return err
	}
	return m.restoreSnapshot(s, true)
}

func (m *Manager) checkOwner(s snapshot) error {
	if s.Owner.PID == 0 {
		raw, err := privatefile.Read(m.lockPath(), 64)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("netenv: legacy owner record unreadable; journal retained: %w", err)
		}
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil || pid <= 0 {
				return errors.New("netenv: legacy owner record invalid; journal retained")
			}
			s.Owner.PID = pid
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

func (m *Manager) upgradeSnapshot(s *snapshot) error {
	if s.Version == 3 {
		return nil
	}
	if len(s.importRaw) != 0 {
		archive := filepath.Join(m.Dir, "journal-imports", s.ID+".json")
		if err := privatefile.WriteNew(archive, s.importRaw); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("netenv: preserve original imported journal: %w", err)
			}
			existing, err := privatefile.Read(archive, journalSizeLimit)
			if err != nil || !reflect.DeepEqual(existing, s.importRaw) {
				return errors.Join(errors.New("netenv: imported journal archive differs; evidence retained"), err)
			}
		}
	}
	s.Version, s.RecoveryOnly = 3, true
	s.fillLegacy()
	// Pin imported data before registry mutation. Resolved unknown bypasses
	// and the exact-address contamination rule must survive partial recovery.
	return m.saveSnapshot(*s)
}

func (m *Manager) restoreSnapshot(s snapshot, force bool) error {
	defer func() {
		if m.notify != nil {
			m.notify()
		}
	}()
	if err := m.upgradeSnapshot(&s); err != nil {
		return err
	}
	if force || s.Touched[regKeyPath] {
		b := s.bundle(regKeyPath)
		// RestoreFrom already pinned the operator-authorized current values;
		// even that path refuses a later competing change during journaling.
		if err := m.restoreBundle(regKeyPath, &b, func(b settingsBundle) error {
			s.setBundle(regKeyPath, b)
			return m.saveSnapshot(s)
		}); err != nil {
			// WinINET failure must remain fatal/retryable, but it is not a
			// reason to leave writable browser policies pointing to a dead
			// local listener. Their evidence stays in the active journal until
			// mandatory restoration can finish and detach any remaining work.
			for _, path := range chromiumPolicyPaths {
				if !s.Touched[path] {
					continue
				}
				b := s.bundle(path)
				if policyErr := m.restoreBundle(path, &b, func(b settingsBundle) error {
					s.setBundle(path, b)
					return m.saveSnapshot(s)
				}); policyErr != nil {
					m.warn(path, "cleanup pending in active recovery journal", policyErr)
					m.result.PendingPolicies = appendUnique(m.result.PendingPolicies, path)
				}
			}
			return err // mandatory restoration keeps the active journal/lease
		}
	}
	// Detach optional evidence BEFORE releasing mandatory session ownership.
	// The no-replace, per-session record also works when an older pending file
	// is corrupt or unreadable; that file is never overwritten or discarded.
	if err := m.detachPolicies(s, force); err != nil {
		return fmt.Errorf("netenv: could not preserve pending policy cleanup; active journal retained: %w", err)
	}
	if err := removeRecoveryState(m.lockPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := removeRecoveryState(m.snapPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m.retryPendingPolicies()
	m.releaseLease()
	return nil
}

func backupSnapshot(raw []byte) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Join(filepath.Dir(exe), "settings-backup")
	if err := privatefile.EnsureDir(dir); err != nil {
		return
	}
	name := "network-settings-" + time.Now().Format("20060102-150405.000000000") + ".json"
	if err := privatefile.WriteNew(filepath.Join(dir, name), raw); err != nil {
		return
	}
	entries, _ := filepath.Glob(filepath.Join(dir, "network-settings-*.json"))
	sort.Strings(entries)
	for len(entries) > 3 {
		_ = os.Remove(entries[0])
		entries = entries[1:]
	}
	bat := "@echo off\r\n\"%~dp0..\\" + filepath.Base(exe) + "\" --restore-from \"%~dp0" + name + "\"\r\nif errorlevel 1 (echo Restore failed - keep the backup and retry.) else (echo Recovery attempted; review any pending-policy warnings.)\r\npause\r\n"
	_ = privatefile.Write(filepath.Join(dir, "restore-network.bat"), []byte(bat))
}
