// Package privatefile creates user-private local state. Windows permission
// bits alone are not ACLs; the platform adapter installs a protected DACL.
// This protects against other ordinary users, not malicious same-user code.
package privatefile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
)

func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private state directory must not be a link")
	}
	return restrict(path, true)
}

func Protect(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("private state must be a regular file, not a link")
	}
	return restrict(path, false)
}

// WriteNew never overwrites existing user state. A private temporary file is
// flushed before an atomic no-replace link exposes the complete file.
func WriteNew(path string, data []byte) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".private-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := restrict(tmp, false); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Write replaces only a regular file within a private directory. The caller
// owns synchronization; this is not an inter-process read/modify/write lock.
func Write(path string, data []byte) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace linked private state")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".private-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := restrict(tmp, false); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := replace(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Read bounds private config/state before decoding and refuses linked files.
func Read(path string, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return nil, errors.New("invalid private state size limit")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, errors.New("private state is linked or oversized")
	}
	if err := Protect(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("private state changed while opening")
	}
	// Bound the read itself, not just the pre-open size. A concurrently
	// growing file must not allocate unbounded memory before validation.
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("private state exceeds size limit")
	}
	return data, nil
}
