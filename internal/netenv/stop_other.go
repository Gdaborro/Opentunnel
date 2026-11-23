//go:build !windows

package netenv

import "errors"

func RecordProcessOwner() error { return nil }

func StopClient() error { return errors.New("checked process stop is supported only on Windows") }
