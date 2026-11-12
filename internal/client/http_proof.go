package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/protocol"
)

func SignHTTPRequest(req *http.Request, body []byte) error {
	ts, err := NewTokenStore()
	if err != nil {
		return err
	}
	if _, err := ts.EnsureSSHKey(); err != nil {
		return err
	}
	raw, err := os.ReadFile(ts.SSHPrivatePath())
	if err != nil {
		return err
	}
	key, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return errors.New("device signing key unavailable")
	}
	var ed ed25519.PrivateKey
	switch key := key.(type) {
	case ed25519.PrivateKey:
		ed = key
	case *ed25519.PrivateKey:
		ed = *key
	default:
		return errors.New("device key is not Ed25519")
	}
	at := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(protocol.RandomSalt())
	msg := protocol.HTTPProofMsg(req.Method, req.URL.EscapedPath(), at, nonce, body)
	req.Header.Set("X-Otu-Time", at)
	req.Header.Set("X-Otu-Nonce", nonce)
	req.Header.Set("X-Otu-Proof", base64.StdEncoding.EncodeToString(ed25519.Sign(ed, msg)))
	return nil
}
