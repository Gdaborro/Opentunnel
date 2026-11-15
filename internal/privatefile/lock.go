package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

var ErrLocked = errors.New("private state is busy in another process; retry after that operation completes")

// TryLock holds a native exclusive lock on a stable, private regular file.
// The file stays in place after release: removing it would let a competing
// process lock a new inode while an old holder still owns the previous one.
func TryLock(path string) (func(), error) {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := WriteNew(path, nil); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := Protect(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("private lock file changed while opening")
	}
	unlock, err := lockFile(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { unlock(); _ = f.Close() }) }, nil
}
