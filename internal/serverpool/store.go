package serverpool

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/privatefile"
)

type Store struct{ Dir string }

const MaxProfiles = 64

// Serialize read/modify/write operations in-process and between CLI processes.
// An inter-process lock is nonblocking: an interrupted operation cannot leave
// an immortal owner marker or permit a concurrent signed-profile rollback.
var storeMu sync.Mutex

func (s Store) lock() (func(), error) {
	storeMu.Lock()
	unlock, err := privatefile.TryLock(filepath.Join(s.Dir, "server-profiles.lock"))
	if err != nil {
		storeMu.Unlock()
		return nil, err
	}
	return func() { unlock(); storeMu.Unlock() }, nil
}

func (s Store) path(id string) (string, error) {
	if !ValidID(id) {
		return "", errors.New("invalid server pool ID")
	}
	return filepath.Join(s.Dir, "server-profiles", id+".json"), nil
}

func (s Store) Load(id string, now time.Time) (Profile, error) {
	unlock, err := s.lock()
	if err != nil {
		return Profile{}, err
	}
	defer unlock()
	return s.load(id, now)
}

func (s Store) load(id string, now time.Time) (Profile, error) {
	path, err := s.path(id)
	if err != nil {
		return Profile{}, err
	}
	raw, err := privatefile.Read(path, MaxProfileSize)
	if err != nil {
		return Profile{}, err
	}
	p, err := Decode(raw)
	if err == nil {
		err = p.Verify(now)
	}
	if err == nil && p.ID != id {
		return Profile{}, errors.New("stored profile does not match the requested pool ID")
	}
	return p, err
}

// Import requires explicit user consent. A self-signature authenticates updates
// under the accepted operator key; it cannot establish initial operator trust.
func (s Store) Import(p Profile, consent bool, now time.Time) error {
	if !consent {
		return errors.New("explicit consent is required before trusting another server operator")
	}
	if err := p.Verify(now); err != nil {
		return err
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	path, err := s.path(p.ID)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if len(raw) > MaxProfileSize {
		return errors.New("encoded server pool profile exceeds size limit")
	}
	previous, err := privatefile.Read(path, MaxProfileSize)
	if errors.Is(err, os.ErrNotExist) {
		entries, err := s.entries()
		if err != nil {
			return err
		}
		if len(entries) >= MaxProfiles {
			return errors.New("server profile capacity reached")
		}
		return privatefile.WriteNew(path, raw)
	}
	if err != nil {
		return err // never discard unreadable previously trusted state
	}
	old, err := Decode(previous)
	if err != nil {
		return err
	}
	// Validate old signatures even if their profile has now expired.
	if err := old.Verify(time.Unix(old.IssuedAt, 0)); err != nil || old.ID != p.ID || old.OperatorKey != p.OperatorKey || old.AuthorityID != p.AuthorityID {
		return errors.New("stored pool trust is corrupt or belongs to another operator")
	}
	canonicalOld, _ := json.Marshal(old)
	canonicalNew, _ := json.Marshal(p)
	if string(canonicalOld) == string(canonicalNew) {
		return nil
	}
	if p.IssuedAt <= old.IssuedAt || p.ExpiresAt < old.ExpiresAt {
		return errors.New("server pool rollback or conflicting same-version profile refused")
	}
	if old.RequireChannelAuth && !p.RequireChannelAuth {
		return errors.New("server pool authentication downgrade refused; upgraded device identities remain connection-bound")
	}
	return privatefile.Write(path, raw)
}

func (s Store) Select(id string, now time.Time) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if id != "default" {
		if _, err := s.load(id, now); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(struct {
		ID string `json:"id"`
	}{id})
	return privatefile.Write(filepath.Join(s.Dir, "selected-server-pool.json"), raw)
}

func (s Store) Selected() (string, error) {
	unlock, err := s.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	raw, err := privatefile.Read(filepath.Join(s.Dir, "selected-server-pool.json"), 256)
	if errors.Is(err, os.ErrNotExist) {
		return "default", nil
	}
	if err != nil {
		return "", err
	}
	var selection struct {
		ID string `json:"id"`
	}
	if err := DecodeStrict(raw, &selection); err != nil || (selection.ID != "default" && !ValidID(selection.ID)) {
		return "", errors.New("server pool selection is corrupt; refusing to switch operators silently")
	}
	return selection.ID, nil
}

// entries bounds directory enumeration itself, not just its returned slice.
func (s Store) entries() ([]os.DirEntry, error) {
	dir := filepath.Join(s.Dir, "server-profiles")
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("server profile directory unavailable or linked")
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("server profile directory changed while opening")
	}
	entries, err := f.ReadDir(MaxProfiles + 1)
	if (err != nil && err != io.EOF) || len(entries) > MaxProfiles {
		return nil, errors.New("server profile directory exceeds supported capacity or is unreadable")
	}
	return entries, nil
}

// List includes expired signed profiles so operators can see what needs a
// fresh export. Load and Select still refuse expired profiles for connections.
func (s Store) List(now time.Time) ([]Profile, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	var pools []Profile
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidID(id) {
			return nil, errors.New("server profile filename is invalid")
		}
		path, _ := s.path(id)
		raw, err := privatefile.Read(path, MaxProfileSize)
		if err != nil {
			return nil, err
		}
		p, err := Decode(raw)
		if err != nil {
			return nil, err
		}
		if err := p.Verify(time.Unix(p.IssuedAt, 0)); err != nil || p.ID != id || p.IssuedAt > now.Unix()+300 {
			return nil, errors.New("stored server profile trust is invalid")
		}
		pools = append(pools, p)
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].Name < pools[j].Name })
	return pools, nil
}
