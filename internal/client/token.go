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

	"golang.org/x/crypto/ssh"
)

// TokenStore handles the client's persistent token and hard ban markers.
type TokenStore struct {
	Dir string // %LOCALAPPDATA%\opentunnel
}

type deviceFile struct {
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	DeviceName  string `json:"device_name"`
}

func NewTokenStore() (*TokenStore, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "opentunnel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &TokenStore{Dir: dir}, nil
}

func (s *TokenStore) TokenPath() string { return filepath.Join(s.Dir, "device.json") }
func (s *TokenStore) BanPath() string   { return filepath.Join(s.Dir, "ban.json") }
func (s *TokenStore) SSHPrivatePath() string { return filepath.Join(s.Dir, "device_ssh") }
func (s *TokenStore) SSHPublicPath() string  { return filepath.Join(s.Dir, "device_ssh.pub") }

func (s *TokenStore) LoadOrCreate() (*deviceFile, error) {
	// Check hard ban first — if any marker exists, refuse to create
	if s.IsHardBanned() {
		return nil, fmt.Errorf("device is banned — not generating new token")
	}
	path := s.TokenPath()
	if data, err := os.ReadFile(path); err == nil {
		var df deviceFile
		if json.Unmarshal(data, &df) == nil && df.Token != "" {
			return &df, nil
		}
	}
	// Generate new
	tok := make([]byte, 32)
	rand.Read(tok)
	df := &deviceFile{
		Token:       base64.RawURLEncoding.EncodeToString(tok),
		Fingerprint: deviceFingerprint(),
		DeviceName:  hostname(),
	}
	data, _ := json.MarshalIndent(df, "", "  ")
	os.WriteFile(path, data, 0600)
	return df, nil
}

func (s *TokenStore) IsHardBanned() bool {
	// Check 3 locations: ban.json, registry, device.json.banned
	if _, err := os.Stat(s.BanPath()); err == nil {
		return true
	}
	if isRegistryBanned() {
		return true
	}
	return false
}

func (s *TokenStore) WriteHardBan(reason, duration string) {
	data, _ := json.Marshal(map[string]string{"reason": reason, "duration": duration})
	os.WriteFile(s.BanPath(), data, 0600)
	writeRegistryBan(reason, duration)
}

func (s *TokenStore) EnsureSSHKey() (string, error) {
	privPath := s.SSHPrivatePath()
	pubPath := s.SSHPublicPath()
	if _, err := os.Stat(privPath); err == nil {
		if data, err := os.ReadFile(pubPath); err == nil {
			return string(data), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600); err != nil {
		return "", err
	}
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return "", err
	}
	pubAuthorized := ssh.MarshalAuthorizedKey(pub)
	_ = os.WriteFile(pubPath, pubAuthorized, 0644)
	return string(pubAuthorized), nil
}

func (s *TokenStore) SSHPublicKey() string {
	data, err := os.ReadFile(s.SSHPublicPath())
	if err != nil {
		return ""
	}
	return string(data)
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	return h
}
