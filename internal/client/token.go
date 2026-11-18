package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/version"
)

// TokenStore handles the client's persistent token and hard ban markers.
type TokenStore struct {
	Dir   string // %LOCALAPPDATA%\opentunnel
	Scope string
}

// Many mux dials can ask for the same identity at once. Never mint or
// overwrite competing tokens/keys from those concurrent callers.
var tokenStoreMu sync.Mutex

type deviceFile struct {
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	DeviceName  string `json:"device_name"`
}

// DeviceIdentity is the persistent per-operator device identity, never an
// enrollment-account password or an administrator session.
type DeviceIdentity = deviceFile

func NewTokenStore() (*TokenStore, error) {
	return NewPoolTokenStore("")
}

// Pool state is isolated by the accepted operator key. Root recovery/update
// state remains separate; another operator cannot lift the default pool's ban
// marker, inherit its key/token, or poison its certificate/SSH trust cache.
func NewPoolTokenStore(scope string) (*TokenStore, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, version.ProductName)
	if scope != "" {
		if !serverpool.ValidID(scope) {
			return nil, fmt.Errorf("invalid identity scope")
		}
		dir = filepath.Join(dir, "server-identities", scope)
	}
	if err := privatefile.EnsureDir(dir); err != nil {
		return nil, err
	}
	return &TokenStore{Dir: dir, Scope: scope}, nil
}

func (s *TokenStore) TokenPath() string      { return filepath.Join(s.Dir, "device.json") }
func (s *TokenStore) BanPath() string        { return filepath.Join(s.Dir, "ban.json") }
func (s *TokenStore) SSHPrivatePath() string { return filepath.Join(s.Dir, "device_ssh") }
func (s *TokenStore) SSHPublicPath() string  { return filepath.Join(s.Dir, "device_ssh.pub") }
func (s *TokenStore) approvedPath() string   { return filepath.Join(s.Dir, "approved.flag") }
func (s *TokenStore) keyEstablishedPath() string {
	return filepath.Join(s.Dir, "device-key-established.flag")
}

// MarkApproved records that this device identity has been approved by the
// panel at least once, keyed on the device FINGERPRINT (not the token):
// a forced token rotation or re-registration cannot reset the marker, so
// a middleman-forged "you are a fresh device" state cannot re-open the
// bootstrap channels for a device the panel already trusts.
func (s *TokenStore) MarkApproved(fingerprint string) {
	if fingerprint == "" {
		return
	}
	_ = privatefile.Write(s.approvedPath(), []byte(fingerprint))
}

// EverApproved reports whether an approval verdict ever arrived over a
// trusted channel (pinned HTTPS or in-band) for this device fingerprint.
func (s *TokenStore) EverApproved(fingerprint string) bool {
	data, err := privatefile.Read(s.approvedPath(), 256)
	if err != nil {
		return false
	}
	return string(data) == fingerprint && fingerprint != ""
}

func (s *TokenStore) LoadOrCreate() (*deviceFile, error) {
	tokenStoreMu.Lock()
	defer tokenStoreMu.Unlock()
	// An existing identity always loads: the panel (not the local marker)
	// decides bans now, so a stale marker from an admin unban cannot brick
	// startup before the server is even asked.
	path := s.TokenPath()
	if data, err := privatefile.Read(path, 4<<10); err == nil {
		var df deviceFile
		decodeErr := json.Unmarshal(data, &df)
		if s.Scope != "" {
			decodeErr = serverpool.DecodeStrict(data, &df)
		}
		if decodeErr == nil && df.Token != "" && (s.Scope == "" || (df.Fingerprint != "" && len(df.Token) <= 1024 && len(df.Fingerprint) <= 128 && len(df.DeviceName) <= 64)) {
			return &df, nil
		}
		return nil, fmt.Errorf("device identity file is invalid; refusing to silently replace it")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read device identity: %w", err)
	}
	// Minting a fresh identity while banned stays refused: bans bind to the
	// device key, so deleting device.json must not shed a ban.
	if s.IsHardBanned() {
		return nil, fmt.Errorf("device is banned — not generating new token")
	}
	// Generate new
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("generate device identity: %w", err)
	}
	df := &deviceFile{
		Token:      base64.RawURLEncoding.EncodeToString(tok),
		DeviceName: hostname(),
	}
	if s.Scope != "" {
		// An independent random enrollment fingerprint avoids sharing the
		// machine-derived default fingerprint across self-hosted operators.
		fp := make([]byte, 16)
		if _, err := rand.Read(fp); err != nil {
			return nil, fmt.Errorf("generate scoped identity: %w", err)
		}
		df.Fingerprint = base64.RawURLEncoding.EncodeToString(fp)
	} else {
		df.Fingerprint = deviceFingerprint()
	}
	data, err := json.MarshalIndent(df, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeNewIdentityFile(path, data, 0o600); err != nil {
		if os.IsExist(err) {
			// Another process won the creation race. Use its identity,
			// never the unpersisted one generated by this process.
			stored, rerr := privatefile.Read(path, 4<<10)
			if rerr == nil && json.Unmarshal(stored, df) == nil && df.Token != "" {
				return df, nil
			}
		}
		return nil, fmt.Errorf("persist device identity: %w", err)
	}
	return df, nil
}

func writeNewIdentityFile(path string, data []byte, mode os.FileMode) error {
	return privatefile.WriteNew(path, data)
}

func (s *TokenStore) IsHardBanned() bool {
	// Check 3 locations: ban.json, registry, device.json.banned
	if _, err := os.Stat(s.BanPath()); err == nil {
		return true
	}
	if s.Scope == "" && isRegistryBanned() {
		return true
	}
	return false
}

func (s *TokenStore) WriteHardBan(reason, duration string) {
	data, _ := json.Marshal(map[string]string{"reason": reason, "duration": duration})
	_ = privatefile.Write(s.BanPath(), data)
	if s.Scope == "" {
		writeRegistryBan(reason, duration)
	}
}

// ClearBan removes local hard-ban markers. It is called when the panel
// reports the device is no longer banned (e.g. the admin unbanned it while
// the client was offline): without this, a stale ban.json would refuse
// startup forever and the client would open then instantly close.
func (s *TokenStore) ClearBan() {
	_ = os.Remove(s.BanPath())
	if s.Scope == "" {
		clearRegistryBan()
	}
}

func (s *TokenStore) EnsureSSHKey() (string, error) {
	tokenStoreMu.Lock()
	defer tokenStoreMu.Unlock()
	privPath := s.SSHPrivatePath()
	pubPath := s.SSHPublicPath()
	keyRaw, err := privatefile.Read(privPath, 16<<10)
	if err == nil {
		if err := privatefile.Protect(privPath); err != nil {
			return "", err
		}
	}
	if os.IsNotExist(err) {
		for _, marker := range []string{s.keyEstablishedPath(), s.approvedPath()} {
			if _, markerErr := os.Lstat(marker); markerErr == nil {
				return "", fmt.Errorf("established device private key missing; administrator-assisted recovery required")
			} else if !os.IsNotExist(markerErr) {
				return "", markerErr
			}
		}
		// A surviving public key means a private key was lost, not that a
		// fresh identity should be minted under an already-approved token.
		if _, perr := os.Stat(pubPath); perr == nil {
			return "", fmt.Errorf("device private key missing; administrator-assisted recovery required")
		} else if !os.IsNotExist(perr) {
			return "", perr
		}
		_, priv, kerr := ed25519.GenerateKey(rand.Reader)
		if kerr != nil {
			return "", kerr
		}
		privPEM, kerr := ssh.MarshalPrivateKey(priv, "")
		if kerr != nil {
			return "", kerr
		}
		keyRaw = pem.EncodeToMemory(privPEM)
		if kerr = writeNewIdentityFile(privPath, keyRaw, 0o600); kerr != nil {
			if !os.IsExist(kerr) {
				return "", kerr
			}
			keyRaw, err = privatefile.Read(privPath, 16<<10)
		} else {
			err = nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("read device private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyRaw)
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return "", fmt.Errorf("device private key is invalid; refusing to replace it")
	}
	if _, err := os.Lstat(s.keyEstablishedPath()); os.IsNotExist(err) {
		if err := privatefile.WriteNew(s.keyEstablishedPath(), []byte("established\n")); err != nil && !os.IsExist(err) {
			return "", fmt.Errorf("persist device-key ownership: %w", err)
		}
	} else if err != nil {
		return "", err
	}
	// The public file is a cache, not the identity. Recover it from the
	// private key if missing, stale, or corrupted; never regenerate the key.
	pubAuthorized := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if cached, rerr := privatefile.Read(pubPath, 2048); rerr != nil || string(cached) != string(pubAuthorized) {
		if err := privatefile.Write(pubPath, pubAuthorized); err != nil {
			return "", fmt.Errorf("persist device public key: %w", err)
		}
	}
	return string(pubAuthorized), nil
}

func (s *TokenStore) SSHPublicKey() string {
	pub, err := s.EnsureSSHKey()
	if err != nil {
		return ""
	}
	return pub
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	return h
}
