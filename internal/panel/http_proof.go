package panel

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/protocol"
)

// Read-only legacy status requests remain compatible. State-changing public
// health/heartbeat requests must prove possession of the enrolled device key.
func (h *Handler) verifyHTTPProof(r *http.Request, token string, body []byte) bool {
	at := r.Header.Get("X-Otu-Time")
	nonce := r.Header.Get("X-Otu-Nonce")
	ts, err := strconv.ParseInt(at, 10, 64)
	if err != nil {
		return false
	}
	age := time.Now().Unix() - ts
	if age < -120 || age > 120 {
		return false
	}
	n, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(n) != protocol.SaltSize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Otu-Proof"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.db.SSHPubKey(token)))
	if err != nil {
		return false
	}
	cryptoKey, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	ed, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return false
	}
	if !ed25519.Verify(ed, protocol.HTTPProofMsg(r.Method, r.URL.EscapedPath(), at, nonce, body), sig) {
		return false
	}
	h.proofMu.Lock()
	defer h.proofMu.Unlock()
	if h.proofReplay == nil {
		h.proofReplay = protocol.NewReplayCache(4*time.Minute, 8192)
	}
	return h.proofReplay.CheckAndAdd(n)
}
