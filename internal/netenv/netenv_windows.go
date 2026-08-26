//go:build windows

// Package netenv manages the machine's user-level proxy configuration with a
// guaranteed snapshot/change/restore lifecycle ("zero residue" invariant).
package netenv

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows/registry"

	"golang.org/x/sys/windows"
)

const regKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const (
	optSettingsChanged = 39
	optRefresh         = 37
)

var (
	wininet               = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")
)

func notifySystem() {
	if err := wininet.Load(); err != nil {
		return
	}
	_, _, _ = procInternetSetOption.Call(0, optSettingsChanged, 0, 0)
	_, _, _ = procInternetSetOption.Call(0, optRefresh, 0, 0)
}

type stringVal struct {
	Exists bool   `json:"exists"`
	Data   string `json:"data,omitempty"`
}

type snapshot struct {
	ProxyEnable   uint32    `json:"proxy_enable"`
	ProxyServer   stringVal `json:"proxy_server"`
	ProxyOverride stringVal `json:"proxy_override"`
	AutoConfigURL stringVal `json:"autoconfig_url"`
}

// Manager owns the journal directory (%LOCALAPPDATA%\opentunnel).
type Manager struct{ Dir string }

func NewManager() (*Manager, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return nil, errors.New("netenv: LOCALAPPDATA is not set")
	}
	dir := filepath.Join(base, "opentunnel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Manager{Dir: dir}, nil
}

func (m *Manager) snapPath() string { return filepath.Join(m.Dir, "snapshot.json") }
func (m *Manager) lockPath() string { return filepath.Join(m.Dir, "lock.pid") }

func (m *Manager) hasSnapshot() bool { _, err := os.Stat(m.snapPath()); return err == nil }

// Recover checks for orphaned state from a previous crashed session and
// restores it. Safe to call on every start.
func (m *Manager) Recover() error {
	if !m.hasSnapshot() {
		return nil
	}
	pidFile := m.lockPath()
	stale := true
	if raw, err := os.ReadFile(pidFile); err == nil {
		if pid, perr := strconv.Atoi(string(raw)); perr == nil && processAlive(uint32(pid)) {
			stale = false
		}
	}
	if !stale {
		return errors.New("netenv: another opentunnel client appears to be running")
	}
	if err := m.Restore(); err != nil {
		return err
	}
	fmt.Println("netenv: recovered settings left over from a previous crashed session")
	return nil
}

func processAlive(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}

// Begin snapshots current proxy settings, journals them to disk, then applies
// proxyAddr as the system (per-user) proxy.
func (m *Manager) Begin(proxyAddr string, bypass []string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, regKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("netenv: open registry: %w", err)
	}
	snap := snapshot{}
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		snap.ProxyEnable = uint32(v)
	}
	snap.ProxyServer = readString(k, "ProxyServer")
	snap.ProxyOverride = readString(k, "ProxyOverride")
	snap.AutoConfigURL = readString(k, "AutoConfigURL")
	_ = k.Close()

	raw, err := json.Marshal(&snap)
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.snapPath(), raw, 0o600); err != nil {
		return fmt.Errorf("netenv: write snapshot: %w", err)
	}
	if err := os.WriteFile(m.lockPath(), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return fmt.Errorf("netenv: write lock: %w", err)
	}
	return m.apply(proxyAddr, bypass)
}

func readString(k registry.Key, name string) stringVal {
	v, _, err := k.GetStringValue(name)
	return stringVal{Exists: err == nil, Data: v}
}

func (m *Manager) apply(proxyAddr string, bypass []string) error {
	override := "localhost;127.0.0.1;<local>"
	for _, b := range bypass {
		override += ";" + b
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("netenv: open registry for write: %w", err)
	}
	defer k.Close()
	_ = k.DeleteValue("AutoConfigURL") // PAC would bypass our proxy
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", proxyAddr); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", override); err != nil {
		return err
	}
	notifySystem()
	return nil
}

// Restore reapplies the journaled original settings and removes the journal.
func (m *Manager) Restore() error {
	raw, err := os.ReadFile(m.snapPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var s snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("netenv: corrupt snapshot: %w", err)
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	restoreString(k, "ProxyServer", s.ProxyServer)
	restoreString(k, "ProxyOverride", s.ProxyOverride)
	restoreString(k, "AutoConfigURL", s.AutoConfigURL)
	if err := k.SetDWordValue("ProxyEnable", s.ProxyEnable); err != nil {
		return err
	}
	notifySystem()
	_ = os.Remove(m.snapPath())
	_ = os.Remove(m.lockPath())
	return nil
}

func restoreString(k registry.Key, name string, v stringVal) {
	if v.Exists {
		_ = k.SetStringValue(name, v.Data)
	} else {
		_ = k.DeleteValue(name)
	}
}
