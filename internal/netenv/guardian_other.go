//go:build !windows

package netenv

import "errors"

func StartRecoveryWatcher() error     { return errors.New("recovery helper is Windows-only") }
func runRecoveryWatcher(uint32) error { return errors.New("recovery helper is Windows-only") }
