//go:build !windows

package netenv

// Other platforms configure application proxies manually. The common journal
// engine remains testable with an isolated in-memory settings store.
func NewManager() (*Manager, error) { return &Manager{}, nil }
