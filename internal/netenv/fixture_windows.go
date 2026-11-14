//go:build windows && netenvfixture

package netenv

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/version"
)

// This opt-in build replaces the Windows registry adapter entirely. It cannot
// access HKCU, even if a test forgets to configure its fixture. Production builds
// do not contain this adapter or recognize OTU_NETENV_FIXTURE.
type fixtureSettings struct {
	Keys               map[string]map[string]registryValue `json:"keys"`
	ReadOnlyPolicies   bool                                `json:"read_only_policies,omitempty"`
	DenyMandatoryApply bool                                `json:"deny_mandatory_apply,omitempty"`
	DenyPolicyRestore  bool                                `json:"deny_policy_restore,omitempty"`
}

func NewManager() (*Manager, error) {
	path := os.Getenv("OTU_NETENV_FIXTURE")
	base := os.Getenv("LOCALAPPDATA")
	if path == "" || base == "" || !filepath.IsAbs(path) {
		return nil, errors.New("netenvfixture: absolute fixture path and isolated LOCALAPPDATA are required; no registry adapter exists")
	}
	if _, err := loadFixture(path); err != nil {
		return nil, err
	}
	dir := filepath.Join(base, version.ProductName)
	if err := privatefile.EnsureDir(dir); err != nil {
		return nil, err
	}
	return &Manager{Dir: dir, store: fixtureStore{path: path}, leaseFactory: acquireWindowsLease,
		owner: currentWindowsOwner, ownerAlive: windowsOwnerAlive}, nil
}

type fixtureStore struct{ path string }

func loadFixture(path string) (fixtureSettings, error) {
	f := fixtureSettings{}
	raw, err := privatefile.Read(path, 1<<20)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Keys == nil {
		return f, errors.New("netenvfixture: invalid synthetic settings")
	}
	return f, nil
}

func (s fixtureStore) KeyExists(path string) (bool, error) {
	f, err := loadFixture(s.path)
	_, exists := f.Keys[path]
	return exists, err
}

func (s fixtureStore) Read(path, name string) (registryValue, error) {
	f, err := loadFixture(s.path)
	return f.Keys[path][name], err
}

func (s fixtureStore) Write(path, name string, v registryValue) error {
	f, err := loadFixture(s.path)
	if err != nil {
		return err
	}
	if policyPath(path) && (f.ReadOnlyPolicies || (f.DenyPolicyRestore && (!v.Exists || (name == polMode && v.Text != "fixed_servers")))) {
		return errors.New("netenvfixture: synthetic policy write denied")
	}
	if path == regKeyPath && f.DenyMandatoryApply && name == "ProxyServer" && v.Exists {
		return errors.New("netenvfixture: synthetic mandatory write denied")
	}
	if !v.Exists {
		delete(f.Keys[path], name)
	} else {
		if f.Keys[path] == nil {
			f.Keys[path] = make(map[string]registryValue)
		}
		f.Keys[path][name] = v
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return writeRecoveryState(s.path, raw)
}

func (s fixtureStore) DeleteEmptyKey(path string) error {
	f, err := loadFixture(s.path)
	if err != nil {
		return err
	}
	if len(f.Keys[path]) != 0 {
		return nil
	}
	if f.ReadOnlyPolicies || f.DenyPolicyRestore {
		return errors.New("netenvfixture: synthetic policy key deletion denied")
	}
	delete(f.Keys, path)
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return writeRecoveryState(s.path, raw)
}
