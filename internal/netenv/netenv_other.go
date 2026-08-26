//go:build !windows

package netenv

import "errors"

// Manager is a no-op outside Windows; per-user system proxy management is a
// Windows-specific feature. Other platforms configure browsers manually.
type Manager struct{}

func NewManager() (*Manager, error) { return &Manager{}, nil }
func (m *Manager) Recover() error   { return nil }
func (m *Manager) Begin(addr string, bypass []string) error {
	return errors.New("netenv: --auto-proxy is only supported on Windows")
}
func (m *Manager) Restore() error { return nil }
