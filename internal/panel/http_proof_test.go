package panel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/protocol"
)

func signedHealthRequest(body []byte, key ed25519.PrivateKey) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/token/health", bytes.NewReader(body))
	at := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(protocol.RandomSalt())
	r.Header.Set("X-Otu-Time", at)
	r.Header.Set("X-Otu-Nonce", nonce)
	r.Header.Set("X-Otu-Proof", base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.HTTPProofMsg(r.Method, r.URL.EscapedPath(), at, nonce, body))))
	return r
}
func TestHealthRequiresDeviceProofAndRejectsReplay(t *testing.T) {
	db := newTestDB(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	const token = "synthetic-health-token-123456"
	if _, err := db.Exec(`INSERT INTO peers(token,fingerprint,status,created_at,last_seen,ssh_pubkey) VALUES(?,'fixture','approved',datetime('now'),datetime('now'),?)`, token, string(ssh.MarshalAuthorizedKey(sshPub))); err != nil {
		t.Fatal(err)
	}
	h := New(db, NewAuth(db), false)
	body := []byte(`{"token":"` + token + `","version":"fixture","cpu_pct":33}`)
	unsigned := httptest.NewRecorder()
	h.tokenHealth(unsigned, httptest.NewRequest(http.MethodPost, "/api/token/health", bytes.NewReader(body)))
	if unsigned.Code != 403 {
		t.Fatal("bearer token wrote posture without key possession")
	}
	r := signedHealthRequest(body, priv)
	headers := r.Header.Clone()
	rec := httptest.NewRecorder()
	h.tokenHealth(rec, r)
	if rec.Code != 200 {
		t.Fatalf("valid proof: %d %s", rec.Code, rec.Body.String())
	}
	replay := httptest.NewRequest(http.MethodPost, "/api/token/health", bytes.NewReader(body))
	replay.Header = headers
	rec = httptest.NewRecorder()
	h.tokenHealth(rec, replay)
	if rec.Code != 403 {
		t.Fatal("proof replay accepted")
	}
	changed := []byte(`{"token":"` + token + `","version":"forged","cpu_pct":100}`)
	r = signedHealthRequest(body, priv)
	r.Body = ioNop(changed)
	rec = httptest.NewRecorder()
	h.tokenHealth(rec, r)
	if rec.Code != 403 {
		t.Fatal("proof did not bind the exact request body")
	}
}

type byteReadCloser struct{ *bytes.Reader }

func (byteReadCloser) Close() error { return nil }
func ioNop(b []byte) byteReadCloser { return byteReadCloser{bytes.NewReader(b)} }
