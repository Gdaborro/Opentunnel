package panel

import (
	"context"
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
	return h.verifyKeyHTTPProof(r, h.db.SSHPubKey(token), body)
}

// During enrollment the new key is not yet in the DB. A short-lived signed
// request proves its possession; the transaction later refuses key substitution
// for existing identities. Login is an additional enrollment gate, never approval.
func (h *Handler) verifyKeyHTTPProof(r *http.Request, publicKey string, body []byte) bool {
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
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
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
	if h.poolID != "" {
		return h.db.claimPoolHTTPProof(r.Context(), nonce, ts+120)
	}
	h.proofMu.Lock()
	defer h.proofMu.Unlock()
	if h.proofReplay == nil {
		h.proofReplay = protocol.NewReplayCache(4*time.Minute, 8192)
	}
	return h.proofReplay.CheckAndAdd(n)
}

// Pool requests share a bounded durable nonce journal across panel processes
// and restarts. Only expired proofs are removed; capacity pressure fails
// closed instead of evicting still-valid requests or allowing a replay.
func (db *DB) claimPoolHTTPProof(parent context.Context, nonce string, validUntil int64) bool {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM pool_http_proofs WHERE valid_until<?`, time.Now().Unix()); err != nil {
		return false
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pool_http_proofs`).Scan(&count); err != nil || count >= 8192 {
		return false
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pool_http_proofs(nonce,valid_until) VALUES(?,?)`, nonce, validUntil); err != nil {
		return false
	}
	return tx.Commit() == nil
}
