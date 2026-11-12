package client

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"opentunnel/internal/privatefile"
)

const updateJournalName = "update-transaction.json"

var errReplacementStillRunning = errors.New("replacement termination could not be confirmed; recovery evidence retained")

type updateTransaction struct {
	Version        int      `json:"version"`
	Executable     string   `json:"executable"`
	Staged         string   `json:"staged"`
	Backup         string   `json:"backup"`
	SHA256         string   `json:"sha256"`
	PreviousSHA256 string   `json:"previous_sha256"`
	Parent         int      `json:"parent"`
	Helper         int      `json:"helper"`
	Token          string   `json:"token"`
	Args           []string `json:"args"`
	ReadyFile      string   `json:"ready_file"`
	StartedAt      int64    `json:"started_at"`
}

// armReplacement leaves the running executable untouched until a separate
// verified helper has armed and the parent has completed graceful shutdown.
// The helper replaces, checks actual child readiness and rolls back on failure.
func armReplacement(ctx context.Context, exe, staged, digest string) error {
	store, err := NewTokenStore()
	if err != nil {
		return err
	}
	dir := filepath.Join(store.Dir, "updates")
	if err := privatefile.EnsureDir(dir); err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:8])
	tx := updateTransaction{Version: 1, Executable: exe, Staged: staged, Backup: exe + ".old-" + id, SHA256: digest, Parent: os.Getpid(), Token: base64.RawURLEncoding.EncodeToString(nonce[:]), Args: append([]string(nil), os.Args[1:]...), ReadyFile: filepath.Join(dir, "ready-"+id), StartedAt: time.Now().Unix()}
	tx.PreviousSHA256, err = fileDigest(exe)
	if err != nil {
		return err
	}
	journal := filepath.Join(dir, updateJournalName)
	raw, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	if err := privatefile.WriteNew(journal, raw); err != nil {
		return errors.New("another update transaction requires recovery")
	}
	cmd := exec.Command(exe, "-update-supervise", journal)
	prepareUpdateHelper(cmd)
	cmd.Env = withoutUpdateEnvironment(os.Environ())
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = os.Remove(journal)
		return err
	}
	defer out.Close()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = os.Remove(journal)
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(out, 128)).ReadString('\n')
		if err == nil && strings.TrimSpace(line) != "armed" {
			err = errors.New("invalid update-helper readiness")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err == nil {
			return nil
		}
		_ = cmd.Process.Kill()
		<-exited
		_ = os.Remove(journal)
		return errors.New("update helper did not arm")
	case <-exited:
		_ = os.Remove(journal)
		return errors.New("update helper exited before arming")
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-exited
		_ = os.Remove(journal)
		return ctx.Err()
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
		_ = os.Remove(journal)
		return errors.New("update helper readiness timed out; current executable unchanged")
	}
}

func readUpdateTransaction(path string) (updateTransaction, error) {
	var tx updateTransaction
	raw, err := privatefile.Read(path, 32<<10)
	if err != nil {
		return tx, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tx); err != nil {
		return tx, errors.New("invalid update recovery journal")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return tx, errors.New("trailing update journal data")
	}
	if tx.Version != 1 || tx.Parent <= 0 || tx.Helper < 0 || len(tx.Token) != 43 || len(tx.Args) > 64 || tx.StartedAt <= 0 || tx.StartedAt > time.Now().Unix()+120 {
		return tx, errors.New("invalid or expired update transaction")
	}
	if nonce, err := base64.RawURLEncoding.DecodeString(tx.Token); err != nil || len(nonce) != 32 {
		return tx, errors.New("invalid update readiness token")
	}
	// Check canonical paths and basenames together. A string prefix alone
	// accepted '.old-subdir/../../other-file' as an executable backup.
	for _, value := range []string{path, tx.Executable, tx.Staged, tx.Backup, tx.ReadyFile} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return tx, errors.New("update paths must be absolute and canonical")
		}
	}
	if filepath.Base(path) != updateJournalName ||
		!sameExecutablePath(filepath.Dir(tx.Staged), filepath.Dir(tx.Executable)) ||
		!sameExecutablePath(filepath.Dir(tx.Backup), filepath.Dir(tx.Executable)) ||
		!strings.HasPrefix(filepath.Base(tx.Staged), filepath.Base(tx.Executable)+".new-") ||
		!strings.HasPrefix(filepath.Base(tx.Backup), filepath.Base(tx.Executable)+".old-") ||
		!sameExecutablePath(filepath.Dir(tx.ReadyFile), filepath.Dir(path)) ||
		!strings.HasPrefix(filepath.Base(tx.ReadyFile), "ready-") || sameExecutablePath(tx.ReadyFile, path) {
		return tx, errors.New("update paths escaped the executable or transaction directory")
	}
	if digest, err := hex.DecodeString(tx.SHA256); err != nil || len(digest) != 32 {
		return tx, errors.New("invalid update digest")
	}
	if digest, err := hex.DecodeString(tx.PreviousSHA256); err != nil || len(digest) != 32 {
		return tx, errors.New("invalid rollback digest")
	}
	for _, arg := range tx.Args {
		if len(arg) > 4096 {
			return tx, errors.New("update argument too long")
		}
	}
	return tx, nil
}

// RunUpdateHelper is called before ordinary startup. It cannot execute a
// journal selected by the network: armReplacement writes a private journal
// after binary signature verification and parent identity is checked again.
func RunUpdateHelper(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "-update-supervise" {
		return false, nil
	}
	if len(args) != 2 {
		return true, errors.New("invalid update helper arguments")
	}
	tx, err := readUpdateTransaction(args[1])
	if err != nil {
		return true, err
	}
	if time.Now().Unix()-tx.StartedAt > 3600 {
		return true, errors.New("stale update cannot be executed; use verified rollback recovery")
	}
	exe, err := os.Executable()
	if err != nil {
		return true, err
	}
	if !sameExecutablePath(exe, tx.Executable) {
		return true, errors.New("update helper executable mismatch")
	}
	if err := validateActualUpdateParent(tx.Parent, tx.Executable); err != nil {
		return true, err
	}
	if err := verifyStagedUpdate(tx); err != nil {
		return true, err
	}
	tx.Helper = os.Getpid()
	updated, err := json.Marshal(tx)
	if err != nil {
		return true, err
	}
	if err := privatefile.Write(args[1], updated); err != nil {
		return true, err
	}
	if _, err := fmt.Fprintln(os.Stdout, "armed"); err != nil {
		return true, err
	}
	if err := waitParentExit(tx.Parent, 60*time.Second); err != nil {
		return true, err
	}
	return true, executeUpdateTransaction(args[1], tx)
}

func verifyStagedUpdate(tx updateTransaction) error {
	info, err := os.Lstat(tx.Staged)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return errors.New("staged update unavailable or invalid")
	}
	f, err := os.Open(tx.Staged)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 64<<20+1)); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), tx.SHA256) {
		return errors.New("staged update changed after signature verification")
	}
	return nil
}

func executeUpdateTransaction(journal string, tx updateTransaction) error {
	previous, err := fileDigest(tx.Executable)
	if err != nil || !strings.EqualFold(previous, tx.PreviousSHA256) {
		return errors.New("current executable changed before replacement; transaction retained")
	}
	if err := verifyStagedUpdate(tx); err != nil {
		return err
	}
	err = replaceExecutable(tx.Executable, tx.Staged, tx.Backup, func() error {
		installed, err := fileDigest(tx.Executable)
		if err != nil || !strings.EqualFold(installed, tx.SHA256) {
			return errors.New("installed replacement digest changed before launch")
		}
		cmd := exec.Command(tx.Executable, tx.Args...)
		prepareUpdateHelper(cmd)
		cmd.Env = append(withoutUpdateEnvironment(os.Environ()), "OTU_UPDATE_PARENT_PID="+fmt.Sprint(tx.Parent), "OTU_UPDATE_READY_FILE="+tx.ReadyFile, "OTU_UPDATE_READY_TOKEN="+tx.Token)
		if err := cmd.Start(); err != nil {
			return err
		}
		exited := make(chan error, 1)
		go func() { defer close(exited); exited <- cmd.Wait() }()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if err := waitReplacementReady(ctx, tx.ReadyFile, tx.Token, exited); err != nil {
			return errors.Join(err, stopReplacement(cmd, exited))
		}
		_ = os.Remove(tx.ReadyFile)
		if err := os.Remove(journal); err != nil {
			return errors.Join(errors.New("update commit journal could not be removed"), stopReplacement(cmd, exited))
		}
		return nil
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, errReplacementStillRunning) {
		return err
	}
	// replaceExecutable has checked rollback of the failed new file. Only
	// re-launch the previous executable once its path is restored; never
	// claim recovery while accidentally executing the failed replacement.
	if restored, restoreErr := fileDigest(tx.Executable); restoreErr != nil || !strings.EqualFold(restored, tx.PreviousSHA256) {
		return errors.Join(err, errors.New("update backup retained; automatic recovery could not restore the original path"))
	}
	_ = os.Remove(tx.ReadyFile)
	if removeErr := os.Remove(journal); removeErr != nil {
		return errors.Join(err, errors.New("rollback restored original but journal removal failed"))
	}
	old := exec.Command(tx.Executable, tx.Args...)
	prepareUpdateHelper(old)
	old.Env = append(withoutUpdateEnvironment(os.Environ()), "OTU_UPDATE_PARENT_PID="+fmt.Sprint(tx.Parent))
	if startErr := old.Start(); startErr != nil {
		return errors.Join(err, errors.New("previous client could not restart after rollback"))
	}
	go func() { _ = old.Wait() }()
	return err
}

func stopReplacement(cmd *exec.Cmd, exited <-chan error) error {
	select {
	case <-exited:
		return nil
	default:
	}
	_ = cmd.Process.Kill()
	select {
	case <-exited:
		return nil
	case <-time.After(5 * time.Second):
		return errReplacementStillRunning
	}
}

func fileDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return "", errors.New("invalid executable for digest")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 64<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// waitReplacementReady accepts a private per-transaction token written only
// after local listeners, settings journal and companions initialize, then
// checks a short stability window. A process Start success is not readiness.
func waitReplacementReady(ctx context.Context, file, token string, exited <-chan error) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return errors.New("replacement readiness timed out")
		case <-exited:
			return errors.New("replacement exited before readiness")
		case <-ticker.C:
			data, err := privatefile.Read(file, 128)
			if err == nil && subtle.ConstantTimeCompare(data, []byte(token)) == 1 {
				stable := time.NewTimer(2 * time.Second)
				select {
				case <-ctx.Done():
					stable.Stop()
					return ctx.Err()
				case <-exited:
					stable.Stop()
					return errors.New("replacement exited during readiness stability check")
				case <-stable.C:
					return nil
				}
			}
		}
	}
}

func ReportUpdateReady() error {
	file, token := os.Getenv("OTU_UPDATE_READY_FILE"), os.Getenv("OTU_UPDATE_READY_TOKEN")
	_ = os.Unsetenv("OTU_UPDATE_READY_FILE")
	_ = os.Unsetenv("OTU_UPDATE_READY_TOKEN")
	if file == "" && token == "" {
		return nil
	}
	if len(token) != 43 || !filepath.IsAbs(file) || !strings.HasPrefix(filepath.Base(file), "ready-") {
		return errors.New("invalid replacement readiness parameters")
	}
	return privatefile.WriteNew(file, []byte(token))
}

var ErrUpdateInProgress = errors.New("another verified update helper is still active")

// RecoverPendingUpdate runs before listeners/settings on the next startup.
// Unfinished transactions roll back only to a digest-verified previous file.
func RecoverPendingUpdate() (restarted bool, err error) {
	store, err := NewTokenStore()
	if err != nil {
		return false, err
	}
	journal := filepath.Join(store.Dir, "updates", updateJournalName)
	if _, err := os.Stat(journal); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	tx, err := readUpdateTransaction(journal)
	if err != nil {
		return false, err
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	if !sameExecutablePath(exe, tx.Executable) {
		return false, errors.New("pending update belongs to a different install; journal retained")
	}
	for _, pid := range []int{tx.Helper, tx.Parent} {
		if pid <= 0 || pid == os.Getpid() {
			continue
		}
		alive, err := updateProcessAlive(pid, tx.Executable, tx.Backup)
		if err != nil {
			return false, err
		}
		if alive {
			return false, ErrUpdateInProgress
		}
	}
	current, err := fileDigest(exe)
	if err != nil {
		return false, err
	}
	if strings.EqualFold(current, tx.PreviousSHA256) {
		if err := os.Remove(journal); err != nil {
			return false, err
		}
		_ = os.Remove(tx.ReadyFile)
		return false, nil
	}
	backup, err := fileDigest(tx.Backup)
	if err != nil || !strings.EqualFold(backup, tx.PreviousSHA256) {
		return false, errors.New("pending update has no verified rollback executable; manual recovery required")
	}
	failed := tx.Executable + ".failed-" + fmt.Sprint(time.Now().UnixNano())
	if err := os.Rename(exe, failed); err != nil {
		return false, err
	}
	if err := os.Rename(tx.Backup, exe); err != nil {
		return false, errors.Join(err, os.Rename(failed, exe))
	}
	if restored, err := fileDigest(exe); err != nil || !strings.EqualFold(restored, tx.PreviousSHA256) {
		return false, errors.New("restored executable did not match the verified rollback digest; journal retained")
	}
	_ = os.Remove(tx.ReadyFile)
	if err := os.Remove(journal); err != nil {
		return false, err
	}
	cmd := exec.Command(exe, tx.Args...)
	prepareUpdateHelper(cmd)
	cmd.Env = append(withoutUpdateEnvironment(os.Environ()), "OTU_UPDATE_PARENT_PID="+fmt.Sprint(os.Getpid()))
	if err := cmd.Start(); err != nil {
		return false, errors.New("verified rollback executable restored but restart failed")
	}
	go func() { _ = cmd.Wait() }()
	return true, nil
}

func withoutUpdateEnvironment(env []string) []string {
	out := make([]string, 0, len(env))
	for _, value := range env {
		key, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "OTU_UPDATE_") {
			out = append(out, value)
		}
	}
	return out
}
func sameExecutablePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
