package panel

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/privatefile"
)

// The approve/revoke hooks can run concurrently. Serialize the complete
// read-modify-write operation, not just the final rename, to avoid lost keys.
var authorizedKeysMu sync.Mutex

// sshkeys.go: authorized_keys hygiene for the ssh tier (1.0.1).
//
// Two audit-round-four findings drive this file:
//
//   - N-11 — `restrict,port-forwarding,permitopen` does NOT prevent
//     command execution: a non-PTY session still runs a shell (and SFTP),
//     so the "forwarding-only" key was effectively a user shell on the
//     relay. Proven empirically against a stock OpenSSH 10.0. The
//     canonical line now carries a forced command that denies every
//     session channel (shell/exec/subsystem/SFTP) while direct-tcpip
//     forwarding — the only channel the tunnel uses — keeps working.
//     Zero fleet impact.
//
//   - N-12 — bans and deletions never touched authorized_keys, so a
//     revoked device kept its key forever. UpsertAuthorizedKey and
//     RemoveAuthorizedKey make revocation real, and both rewrite the file
//     atomically without discarding unrelated operator entries.

// SSHForcedCommand is the forced command every canonical line carries:
// session channels (shell/exec/subsystem) run this and exit immediately;
// forwarding channels are unaffected.
const SSHForcedCommand = "/bin/false"

// CanonicalSSHPubKey validates one authorized-key line and returns its
// canonical "ssh-ed25519 AAAA..." form (comment and any options dropped).
// Newlines are refused: the registration path used to accept them, and
// the approval hook appended the value verbatim — smuggling extra
// unrestricted keys into root-served authorized_keys. Only ed25519 is
// accepted (the v5 handshake and the ssh tier are ed25519-only).
func CanonicalSSHPubKey(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return "", false
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", false
	}
	if pk.Type() != ssh.KeyAlgoED25519 {
		return "", false
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), true
}

// CanonicalAuthorizedKeyLine builds the full authorized_keys entry for a
// validated public key (see the file header for why command= is here).
func CanonicalAuthorizedKeyLine(pub, permitTarget string) string {
	return `command="` + SSHForcedCommand + `",restrict,port-forwarding,permitopen="` + permitTarget + `" ` + pub
}

// lineKey extracts the canonical key portion of one authorized_keys line.
func lineKey(line string) (string, bool) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), true
}

// UpsertAuthorizedKey rewrites path so exactly one canonical line exists
// for pub. Unknown lines/comments are preserved. Missing file = created.
// Returns true
// when the file changed.
func UpsertAuthorizedKey(path, pub, permitTarget string) (changed bool, err error) {
	if err := validatePermitTarget(permitTarget); err != nil {
		return false, err
	}
	authorizedKeysMu.Lock()
	defer authorizedKeysMu.Unlock()
	pub, ok := CanonicalSSHPubKey(pub)
	if !ok {
		return false, os.ErrInvalid
	}
	want := CanonicalAuthorizedKeyLine(pub, permitTarget)

	var lines []string
	matched := false
	if raw, rerr := readAuthorizedKeys(path); rerr == nil {
		for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			k, kok := lineKey(l)
			if !kok {
				lines = append(lines, l)
				continue
			}
			if k == pub {
				if matched {
					changed = true // exactly one line for this key
					continue
				}
				matched = true
				if strings.TrimSpace(l) != want {
					lines = append(lines, want)
					changed = true
				} else {
					lines = append(lines, l)
				}
				continue
			}
			lines = append(lines, l)
		}
	} else if !os.IsNotExist(rerr) {
		return false, rerr
	}

	found := false
	for _, l := range lines {
		if k, kok := lineKey(l); kok && k == pub {
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, want)
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, writeAuthorizedKeys(path, lines)
}

// ReconcileAuthorizedKeys hardens/deduplicates each explicitly managed desired
// key and adds missing entries. Unrelated operator/legacy lines are preserved.
// ReconcileManagedAuthorizedKeys additionally removes explicit revoked keys;
// absence from pubs alone is never permission to delete unknown operator work.
func ReconcileAuthorizedKeys(path, permitTarget string, pubs []string) (added int, err error) {
	return ReconcileManagedAuthorizedKeys(path, permitTarget, pubs, nil)
}

func ReconcileManagedAuthorizedKeys(path, permitTarget string, pubs, revoked []string) (changed int, err error) {
	return reconcileManagedAuthorizedKeys(path, permitTarget, pubs, revoked, false)
}

func reconcileManagedAuthorizedKeys(path, permitTarget string, pubs, revoked []string, createMissing bool) (changed int, err error) {
	if err := validatePermitTarget(permitTarget); err != nil {
		return 0, err
	}
	authorizedKeysMu.Lock()
	defer authorizedKeysMu.Unlock()
	raw, rerr := readAuthorizedKeys(path)
	missing := os.IsNotExist(rerr)
	if rerr != nil && !(createMissing && missing) {
		return 0, rerr
	}
	desired, denied := map[string]bool{}, map[string]bool{}
	for _, pub := range pubs {
		if key, ok := CanonicalSSHPubKey(pub); ok {
			desired[key] = true
		}
	}
	for _, pub := range revoked {
		if key, ok := CanonicalSSHPubKey(pub); ok {
			denied[key] = true
			delete(desired, key)
		}
	}
	var lines []string
	present := map[string]bool{}
	existing := []string{}
	if len(raw) > 0 {
		existing = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	for _, l := range existing {
		if k, ok := lineKey(l); ok {
			if denied[k] {
				changed++
				continue
			}
			if desired[k] {
				if present[k] {
					changed++
					continue
				}
				present[k] = true
				canonical := CanonicalAuthorizedKeyLine(k, permitTarget)
				if strings.TrimSpace(l) != canonical {
					changed++
				}
				lines = append(lines, canonical)
				continue
			}
		}
		lines = append(lines, l)
	}
	for _, pub := range pubs {
		canon, ok := CanonicalSSHPubKey(pub)
		if !ok || !desired[canon] || present[canon] {
			continue
		}
		lines = append(lines, CanonicalAuthorizedKeyLine(canon, permitTarget))
		present[canon] = true
		changed++
	}
	if changed == 0 && !missing {
		return 0, nil
	}
	return changed, writeAuthorizedKeys(path, lines)
}

func validatePermitTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || host == "" || strings.ContainsAny(target, "\"\\\r\n \t") || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("SSH forwarding target must be an explicit loopback endpoint")
	}
	return nil
}

// sameSSHKey compares a stored authorized key with a freshly presented
// one after canonicalization: comments/options are ignored and malformed
// input never matches.
func sameSSHKey(a, b string) bool {
	ca, okA := CanonicalSSHPubKey(a)
	cb, okB := CanonicalSSHPubKey(b)
	if !okA || !okB {
		return false
	}
	return ca == cb
}

// RemoveAuthorizedKey drops every line whose key matches pub (N-12:
// revocation). Returns true when anything was removed.
func RemoveAuthorizedKey(path, pub string) (bool, error) {
	authorizedKeysMu.Lock()
	defer authorizedKeysMu.Unlock()
	pub, ok := CanonicalSSHPubKey(pub)
	if !ok {
		return false, os.ErrInvalid
	}
	raw, err := readAuthorizedKeys(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var kept []string
	removed := false
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		k, kok := lineKey(l)
		if !kok {
			kept = append(kept, l) // unknown operator work is not ours to discard
			continue
		}
		if k == pub {
			removed = true
			continue
		}
		kept = append(kept, l)
	}
	if !removed {
		return false, nil
	}
	return true, writeAuthorizedKeys(path, kept)
}

// This is operator-owned public-key inventory. Reading it must not change
// permissions or treat an unreadable/linked file as an empty authorization set.
func readAuthorizedKeys(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("SSH inventory is linked or oversized")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("SSH inventory changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("SSH inventory unavailable or oversized")
	}
	return raw, nil
}

// writeAuthorizedKeys writes the list atomically (tmp + rename, 0600).
func writeAuthorizedKeys(path string, lines []string) error {
	out := ""
	if len(lines) > 0 {
		out = strings.Join(lines, "\n") + "\n"
	}
	if len(out) > 1<<20 {
		return errors.New("SSH authorization file exceeds supported capacity")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("refusing to replace linked SSH inventory")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".authorized-keys-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := privatefile.Protect(tmp); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.WriteString(out); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}
