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
	"strings"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"golang.org/x/sys/windows"
)

const regKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// Chromium-family browsers (Chrome, Brave, Edge, Vivaldi, Opera...) read the
// WinINET proxy at startup and ignore later broadcasts in some versions. The
// per-user policy keys below ARE watched live, so we set both: WinINET for
// Edge/Firefox/most apps, and policies for every Chromium fork. All HKCU —
// no UAC, no admin — and journaled for restore like the rest.
var chromiumPolicyPaths = []string{
	`Software\Policies\Google\Chrome`,
	`Software\Policies\Microsoft\Edge`,
	`Software\Policies\BraveSoftware\Brave`,
	`Software\Policies\Vivaldi`,
	`Software\Policies\Chromium`,
}

const (
	polMode   = "ProxyMode"
	polServer = "ProxyServer"
	polBypass = "ProxyBypassList"
)

const (
	optSettingsChanged = 39
	optRefresh         = 37
)

var (
	wininet               = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")

	user32         = windows.NewLazySystemDLL("user32.dll")
	procSendMessageTimeout = user32.NewProc("SendMessageTimeoutW")
)

const (
	wmSettingChange = 0x001A
	hwndBroadcast   = 0xFFFF
	smwtoAbortIfHung = 0x0002
)

// notifySystem tells running apps the proxy changed: the WinINET refresh +
// a broadcast WM_SETTINGCHANGE("Internet Settings"). Chromium's proxy watcher
// (ProxyConfigServiceWin) reacts to the broadcast, so browsers pick up the
// new proxy without a restart in most cases.
func notifySystem() {
	if err := wininet.Load(); err == nil {
		_, _, _ = procInternetSetOption.Call(0, optSettingsChanged, 0, 0)
		_, _, _ = procInternetSetOption.Call(0, optRefresh, 0, 0)
	}
	if err := user32.Load(); err == nil {
		internetSettings, _ := windows.UTF16PtrFromString("Internet Settings")
		_, _, _ = procSendMessageTimeout.Call(
			hwndBroadcast,
			wmSettingChange,
			0,
			uintptr(unsafe.Pointer(internetSettings)),
			smwtoAbortIfHung, 1000, 0,
		)
	}
}

type stringVal struct {
	Exists bool   `json:"exists"`
	Data   string `json:"data,omitempty"`
}

type policySnap struct {
	Mode   stringVal `json:"mode"`
	Server stringVal `json:"server"`
	Bypass stringVal `json:"bypass"`
	// HadKey records whether the policy key existed at all, so restore can
	// remove keys we created instead of leaving empty shells behind.
	HadKey bool `json:"had_key"`
}

type snapshot struct {
	ProxyEnable   uint32                 `json:"proxy_enable"`
	ProxyServer   stringVal              `json:"proxy_server"`
	ProxyOverride stringVal              `json:"proxy_override"`
	AutoConfigURL stringVal              `json:"autoconfig_url"`
	Policies      map[string]policySnap  `json:"policies,omitempty"`
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
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(raw))); perr == nil {
			alive := processAlive(uint32(pid)) && isOtuProcess(uint32(pid))
			stale = !alive
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

// isOtuProcess reports whether the given live pid is one of ours by checking
// its process image path. This defeats PID reuse, where a recycled pid would
// otherwise be mistaken for a live client and trap the proxy settings on.
func isOtuProcess(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return false
	}
	image := strings.ToLower(windows.UTF16ToString(buf[:size]))
	return strings.Contains(image, "otu-client")
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
	snap.Policies = snapshotPolicies()

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
	applyPolicies(proxyAddr, bypassList(override))
	notifySystem()
	return nil
}

// snapshotPolicies records the proxy state of every policy key otu can touch.
// Paths that don't exist yet are recorded with HadKey=false so restore can
// delete keys otu created — leaving zero trace.
func snapshotPolicies() map[string]policySnap {
	out := make(map[string]policySnap)
	for _, path := range chromiumPolicyPaths {
		k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
		if err != nil {
			out[path] = policySnap{HadKey: false}
			continue
		}
		ps := policySnap{Mode: readString(k, polMode), Server: readString(k, polServer), Bypass: readString(k, polBypass), HadKey: true}
		_ = k.Close()
		out[path] = ps
	}
	return out
}

// applyPolicies points every Chromium fork at the tunnel via HKCU policy
// keys, which Chromium watches live (no browser restart needed). On
// managed machines (e.g. school group policy) HKCU\Software\Policies may be
// read-only for the user; we report that once so the user knows a browser
// restart makes WinINET apply instead.
func applyPolicies(proxyAddr string, bypass string) {
	appliedAny := false
	for _, path := range chromiumPolicyPaths {
		k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
		if err != nil {
			k, _, err = registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
			if err != nil {
				continue
			}
		}
		_ = k.SetStringValue(polMode, "fixed_servers")
		_ = k.SetStringValue(polServer, proxyAddr)
		_ = k.SetStringValue(polBypass, strings.ReplaceAll(bypass, ";", ","))
		_ = k.Close()
		appliedAny = true
	}
	if !appliedAny {
		fmt.Println("[i] browser policy keys are locked (managed PC): browsers already open may need a restart to route through otu")
	}
}

// restorePolicies puts back exactly what snapshotPolicies captured. Keys otu
// created are deleted outright (no empty shells left behind); keys that
// existed keep their exact original values.
func restorePolicies(snaps map[string]policySnap) {
	for path, ps := range snaps {
		if !ps.HadKey {
			// otu created this key — remove it entirely. If something added
			// subkeys in the meantime, fall back to clearing our values.
			if err := registry.DeleteKey(registry.CURRENT_USER, path); err == nil {
				continue
			}
			if k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE); err == nil {
				_ = k.DeleteValue(polMode)
				_ = k.DeleteValue(polServer)
				_ = k.DeleteValue(polBypass)
				_ = k.Close()
			}
			continue
		}
		k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
		if err != nil {
			continue
		}
		restoreString(k, polMode, ps.Mode)
		restoreString(k, polServer, ps.Server)
		restoreString(k, polBypass, ps.Bypass)
		_ = k.Close()
	}
}

// bypassList converts the WinINET override string ("a;b;<local>") into the
// comma-separated form Chromium policy expects ("a,b,<local>"). <local> is
// kept as Chromium understands it too.
func bypassList(override string) string {
	parts := strings.Split(override, ";")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return strings.Join(parts, ",")
}

// looksLikeOtuState reports whether a snapshotted proxy state is actually
// otu's own footprint (server = our local proxy + our bypass entries). A
// previous crashed session can journal otu's settings as the "original";
// restoring that would leave otu's server string behind (enabled=0, but
// still a trace). In that case we clear instead.
func looksLikeOtuState(server stringVal, override stringVal, enable uint32) bool {
	if !server.Exists || server.Data == "" {
		return false
	}
	if !strings.HasPrefix(server.Data, "127.0.0.1:1") {
		return false
	}
	// Enable can be 0 in a contaminated chain (a crashed session that was
	// force-restored before the next journal), so the server+bypass
	// signature alone decides.
	o := override.Data
	return strings.Contains(o, "cdn.aborro.dev") || strings.Contains(o, "<local>;")
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
	if looksLikeOtuState(s.ProxyServer, s.ProxyOverride, s.ProxyEnable) {
		// The "original" we captured was itself otu's residue from an
		// earlier crashed session: fall back to a clean no-proxy state.
		s.ProxyServer = stringVal{}
		s.ProxyOverride = stringVal{}
		s.ProxyEnable = 0
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
	if s.Policies != nil {
		restorePolicies(s.Policies)
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
