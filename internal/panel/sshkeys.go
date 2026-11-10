package panel

import (
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

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
//     atomically while dropping malformed lines they encounter.

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
// for pub. Malformed lines found along the way are dropped (legacy rows
// could contain injected material). Missing file = created. Returns true
// when the file changed.
func UpsertAuthorizedKey(path, pub, permitTarget string) (changed bool, err error) {
	pub, ok := CanonicalSSHPubKey(pub)
	if !ok {
		return false, os.ErrInvalid
	}
	want := CanonicalAuthorizedKeyLine(pub, permitTarget)

	var lines []string
	if raw, rerr := os.ReadFile(path); rerr == nil {
		for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			k, kok := lineKey(l)
			if !kok {
				if strings.TrimSpace(l) != "" {
					changed = true // dropped junk
				}
				continue
			}
			if k == pub {
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

// ReconcileAuthorizedKeys adds a canonical line for every key in pubs
// that is missing from path, preserving every existing line (legacy and
// operator entries included). It only ever ADDS: revocation stays an
// explicit action (RemoveAuthorizedKey). This is the startup self-heal
// for a deployment where a rewrite, migration or crash left approved
// devices without their line — exactly the state that left a live device
// retrying an impossible authentication for days (2026-11-05 incident).
func ReconcileAuthorizedKeys(path, permitTarget string, pubs []string) (added int, err error) {
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		return 0, rerr
	}
	var lines []string
	present := map[string]bool{}
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if k, ok := lineKey(l); ok {
			present[k] = true
		}
		lines = append(lines, l)
	}
	for _, pub := range pubs {
		canon, ok := CanonicalSSHPubKey(pub)
		if !ok || present[canon] {
			continue
		}
		lines = append(lines, CanonicalAuthorizedKeyLine(canon, permitTarget))
		present[canon] = true
		added++
	}
	if added == 0 {
		return 0, nil
	}
	return added, writeAuthorizedKeys(path, lines)
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
	pub, ok := CanonicalSSHPubKey(pub)
	if !ok {
		return false, os.ErrInvalid
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var kept []string
	removed := false
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		k, kok := lineKey(l)
		if !kok {
			removed = true // dropping malformed junk; the file changes
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

// writeAuthorizedKeys writes the list atomically (tmp + rename, 0600).
func writeAuthorizedKeys(path string, lines []string) error {
	out := ""
	if len(lines) > 0 {
		out = strings.Join(lines, "\n") + "\n"
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
