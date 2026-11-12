//go:build windows

package netenv

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/version"
)

func NewManager() (*Manager, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return nil, errors.New("netenv: LOCALAPPDATA is not set")
	}
	dir := filepath.Join(base, version.ProductName)
	if err := privatefile.EnsureDir(dir); err != nil {
		return nil, err
	}
	return &Manager{Dir: dir, store: windowsStore{}, notify: notifySystem, leaseFactory: acquireWindowsLease,
		owner: currentWindowsOwner, ownerAlive: windowsOwnerAlive, backup: backupSnapshot}, nil
}

type windowsStore struct{}

func (windowsStore) KeyExists(path string) (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_ = k.Close()
	return true, nil
}

func (windowsStore) Read(path, name string) (registryValue, error) {
	v := registryValue{}
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	defer k.Close()
	size, kind, err := k.GetValue(name, nil)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return v, nil
	}
	if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
		return v, err
	}
	if size > 64<<10 {
		return v, errors.New("netenv: registry value too large to journal")
	}
	v.Exists, v.Kind = true, kind
	switch kind {
	case registry.SZ, registry.EXPAND_SZ:
		v.Text, _, err = k.GetStringValue(name)
	case registry.DWORD, registry.QWORD:
		v.Integer, _, err = k.GetIntegerValue(name)
	case registry.MULTI_SZ:
		v.Strings, _, err = k.GetStringsValue(name)
	case registry.BINARY:
		v.Bytes, _, err = k.GetBinaryValue(name)
	default:
		err = errors.New("netenv: unsupported registry value type; settings left unchanged")
	}
	return v, err
}

func (windowsStore) Write(path, name string, v registryValue) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !v.Exists {
		return nil
	}
	if err != nil && v.Exists {
		k, _, err = registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	}
	if err != nil {
		return err
	}
	defer k.Close()
	if !v.Exists {
		err := k.DeleteValue(name)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return err
	}
	switch v.Kind {
	case registry.SZ:
		return k.SetStringValue(name, v.Text)
	case registry.EXPAND_SZ:
		return k.SetExpandStringValue(name, v.Text)
	case registry.DWORD:
		return k.SetDWordValue(name, uint32(v.Integer))
	case registry.QWORD:
		return k.SetQWordValue(name, v.Integer)
	case registry.MULTI_SZ:
		return k.SetStringsValue(name, v.Strings)
	case registry.BINARY:
		return k.SetBinaryValue(name, v.Bytes)
	default:
		return errors.New("netenv: invalid registry restoration type")
	}
}

func (windowsStore) DeleteEmptyKey(path string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	values, verr := k.ReadValueNames(-1)
	subkeys, serr := k.ReadSubKeyNames(-1)
	_ = k.Close()
	if verr != nil {
		return verr
	}
	if serr != nil {
		return serr
	}
	// Preserve any values/subkeys added by the user or another application.
	if len(values) != 0 || len(subkeys) != 0 {
		return nil
	}
	return registry.DeleteKey(registry.CURRENT_USER, path)
}

func acquireWindowsLease(dir string) (func(), error) {
	path, err := windows.UTF16PtrFromString(filepath.Join(dir, "network-settings.lease"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return nil, ErrAlreadyRunning
	}
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}

func currentWindowsOwner() (journalOwner, error) {
	exe, err := os.Executable()
	if err != nil {
		return journalOwner{}, err
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		return journalOwner{}, err
	}
	return journalOwner{PID: os.Getpid(), Image: exe, Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}, nil
}

func windowsOwnerAlive(o journalOwner) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(o.PID))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false, err
	}
	if code != 259 {
		return false, nil
	} // STILL_ACTIVE
	if o.Created == 0 {
		return isOtuProcess(uint32(o.PID)), nil
	} // legacy journal
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return false, err
	}
	return o.Created == uint64(created.HighDateTime)<<32|uint64(created.LowDateTime), nil
}

func processAlive(pid uint32) bool {
	alive, err := windowsOwnerAlive(journalOwner{PID: int(pid)})
	return err == nil && alive
}

func isOtuProcess(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return false
	}
	name := strings.ToLower(filepath.Base(windows.UTF16ToString(buf[:size])))
	name = strings.TrimSuffix(name, ".old")
	return name == strings.ToLower(version.ProcessID)+".exe" || name == strings.ToLower(version.ProcessID)+"-windows-amd64.exe"
}

var (
	wininet                = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption  = wininet.NewProc("InternetSetOptionW")
	user32                 = windows.NewLazySystemDLL("user32.dll")
	procSendMessageTimeout = user32.NewProc("SendMessageTimeoutW")
)

func notifySystem() {
	if err := wininet.Load(); err == nil {
		_, _, _ = procInternetSetOption.Call(0, 39, 0, 0)
		_, _, _ = procInternetSetOption.Call(0, 37, 0, 0)
	}
	if err := user32.Load(); err == nil {
		name, _ := windows.UTF16PtrFromString("Internet Settings")
		_, _, _ = procSendMessageTimeout.Call(0xffff, 0x001a, 0, uintptr(unsafe.Pointer(name)), 0x0002, 1000, 0)
	}
}
