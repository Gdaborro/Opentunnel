// Package panelproxy authenticates metadata forwarded by the local relay.
package panelproxy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"

	"opentunnel/internal/privatefile"
	"opentunnel/internal/version"
)

const (
	ClientIPHeader     = "X-Otu-Client-IP"
	OriginalHostHeader = "X-Otu-Original-Host"
	SchemeHeader       = "X-Otu-Original-Scheme"
	ProofHeader        = "X-Otu-Proxy-Proof"

	maxClientIPLen         = 128
	maxHostLen             = 1024
	maxMethodLen           = 64
	maxRequestTarget       = 64 << 10
	maxUsedProofs          = 4096
	nonceLen               = 16
	proofTTL               = 15 * time.Second
	MaxBodyBytes     int64 = 2 << 20
)

const (
	keyContext   = "opentunnel/panel-proxy/key/v1\x00"
	proofContext = "opentunnel/panel-proxy/request/v1\x00"
)

var (
	ErrInvalidMetadata      = errors.New("invalid panel proxy metadata")
	ErrInvalidProof         = errors.New("panel proxy authentication failed")
	ErrBodyTooLarge         = errors.New("panel proxy body exceeds proof bound")
	ErrReplayCacheSaturated = errors.New("panel proxy replay cache saturated")
)

// Forwarded is the relay-observed request metadata. A value is available to
// panel handlers only after proof verification or authenticated authority
// forwarding; the HTTP headers alone are never authoritative.
type Forwarded struct {
	ClientIP string
	Scheme   string
	Host     string
}

// Proof holds an immutable derived key and a synchronized bounded single-use
// nonce cache. Relay and panel processes derive the same key independently;
// only the panel's cache consumes proofs.
type Proof struct {
	key [sha256.Size]byte

	mu   sync.Mutex
	used map[[nonceLen]byte]int64
	now  func() time.Time
}

// New derives a domain-separated HMAC key without exposing or persisting the
// TLS private key. Unsupported or missing keys fail closed.
func New(privateKey crypto.PrivateKey) (*Proof, error) {
	if privateKey == nil {
		return nil, errors.New("panel proxy proof requires the relay TLS private key")
	}
	value := reflect.ValueOf(privateKey)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, errors.New("panel proxy proof requires the relay TLS private key")
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, errors.New("panel proxy proof cannot encode the relay TLS private key")
	}
	defer clear(der)
	h := sha256.New()
	_, _ = h.Write([]byte(keyContext))
	_, _ = h.Write(der)
	p := &Proof{used: make(map[[nonceLen]byte]int64), now: time.Now}
	copy(p.key[:], h.Sum(nil))
	return p, nil
}

// Load reads the existing relay key pair without creating or replacing it.
// Empty paths resolve exactly like transport.LoadOrCreateCert's persisted
// defaults, but a missing pair is an error rather than a generation race.
func Load(certFile, keyFile string) (*Proof, error) {
	if certFile == "" || keyFile == "" {
		state := os.Getenv("LOCALAPPDATA")
		if state == "" {
			state = os.TempDir()
		}
		dir := filepath.Join(state, version.ProductName)
		certFile = filepath.Join(dir, "server-cert.pem")
		keyFile = filepath.Join(dir, "server-key.pem")
	}
	certData, err := privatefile.ReadOnly(certFile, 64<<10)
	if err != nil {
		return nil, errors.New("panel proxy relay certificate unavailable")
	}
	keyData, err := privatefile.ReadOnly(keyFile, 16<<10)
	if err != nil {
		return nil, errors.New("panel proxy relay private key unavailable")
	}
	defer clear(keyData)
	pair, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, errors.New("panel proxy relay key pair invalid")
	}
	return New(pair.PrivateKey)
}

// ValidateMetadata rejects values that cannot have one bounded, unambiguous
// representation in the relay-to-panel proof.
func ValidateMetadata(forwarded Forwarded) error {
	if len(forwarded.ClientIP) == 0 || len(forwarded.ClientIP) > maxClientIPLen || net.ParseIP(forwarded.ClientIP) == nil ||
		(forwarded.Scheme != "http" && forwarded.Scheme != "https") ||
		len(forwarded.Host) == 0 || len(forwarded.Host) > maxHostLen || !httpguts.ValidHostHeader(forwarded.Host) {
		return ErrInvalidMetadata
	}
	return nil
}

// Stamp overwrites all forwarded metadata and authenticates that tuple plus
// the outgoing method, request target, bounded body, expiry, and random nonce.
// Call it after reverse-proxy path rewriting so the panel hashes the same URI.
func (p *Proof) Stamp(r *http.Request, clientIP, scheme, host string) error {
	r.Header.Del(ProofHeader)
	r.Header.Set(ClientIPHeader, clientIP)
	r.Header.Set(OriginalHostHeader, host)
	r.Header.Set(SchemeHeader, scheme)
	forwarded := Forwarded{ClientIP: clientIP, Scheme: scheme, Host: host}
	if p == nil || p.used == nil {
		return errors.New("panel proxy proof is unavailable")
	}
	if err := ValidateMetadata(forwarded); err != nil {
		return err
	}
	method, target, body, err := requestDigest(r)
	if err != nil {
		return err
	}
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return errors.New("panel proxy nonce unavailable")
	}
	expires := p.clock().Add(proofTTL).Unix()
	sum := p.sum(forwarded, method, target, body, nonce, expires)
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce[:])
	encodedMAC := base64.RawURLEncoding.EncodeToString(sum[:])
	r.Header.Set(ProofHeader, "v1."+encodedNonce+"."+strconv.FormatInt(expires, 10)+"."+encodedMAC)
	return nil
}

// Verify authenticates one bounded request and atomically consumes its nonce.
// A proof cannot be replayed or transplanted to another method, URI, or body.
func (p *Proof) Verify(r *http.Request) (Forwarded, bool) {
	forwarded, err := p.verify(r)
	return forwarded, err == nil
}

func (p *Proof) verify(r *http.Request) (Forwarded, error) {
	var forwarded Forwarded
	if p == nil || p.used == nil || r == nil {
		return forwarded, ErrInvalidProof
	}
	encoded, ok := singleHeader(r.Header, ProofHeader)
	if !ok || len(encoded) > 128 {
		return forwarded, ErrInvalidProof
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return Forwarded{}, ErrInvalidProof
	}
	nonceRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(nonceRaw) != nonceLen {
		return Forwarded{}, ErrInvalidProof
	}
	var nonce [nonceLen]byte
	copy(nonce[:], nonceRaw)
	expires, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return Forwarded{}, ErrInvalidProof
	}
	now := p.clock().Unix()
	if expires <= now || expires > now+int64(proofTTL/time.Second)+1 {
		return Forwarded{}, ErrInvalidProof
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil || len(got) != sha256.Size {
		return Forwarded{}, ErrInvalidProof
	}
	values := make([]string, 3)
	for i, name := range []string{ClientIPHeader, SchemeHeader, OriginalHostHeader} {
		values[i], ok = singleHeader(r.Header, name)
		if !ok {
			return Forwarded{}, ErrInvalidProof
		}
	}
	forwarded = Forwarded{ClientIP: values[0], Scheme: values[1], Host: values[2]}
	if ValidateMetadata(forwarded) != nil {
		return Forwarded{}, ErrInvalidProof
	}
	method, target, body, err := requestDigest(r)
	if err != nil {
		return Forwarded{}, err
	}
	// Buffering a bounded body can still cross the short proof lifetime.
	// Recheck both bounds with fresh time before consuming replay state.
	now = p.clock().Unix()
	if expires <= now || expires > now+int64(proofTTL/time.Second)+1 {
		return Forwarded{}, ErrInvalidProof
	}
	want := p.sum(forwarded, method, target, body, nonce, expires)
	if !hmac.Equal(got, want[:]) {
		return Forwarded{}, ErrInvalidProof
	}
	if err := p.consume(nonce, expires, now); err != nil {
		return Forwarded{}, err
	}
	return forwarded, nil
}

// HasForwardingMetadata reports whether any relay-owned field is present,
// including a non-canonical or empty value that must not be silently ignored.
func HasForwardingMetadata(r *http.Request) bool {
	if r == nil {
		return false
	}
	for name := range r.Header {
		if strings.EqualFold(name, ClientIPHeader) || strings.EqualFold(name, SchemeHeader) ||
			strings.EqualFold(name, OriginalHostHeader) || strings.EqualFold(name, ProofHeader) {
			return true
		}
	}
	return false
}

// AuthenticateStrict preserves header-free direct requests and existing
// authenticated authority metadata, but rejects every unverified relay field.
func (p *Proof) AuthenticateStrict(r *http.Request) (*http.Request, error) {
	if r == nil {
		return r, ErrInvalidProof
	}
	if _, ok := FromRequest(r); ok || !HasForwardingMetadata(r) {
		return r, nil
	}
	forwarded, err := p.verify(r)
	if err != nil {
		return r, err
	}
	return withForwarded(r, forwarded), nil
}

// Authenticate attaches verified metadata to a cloned request. Callers that
// route requests should use AuthenticateStrict and reject its error.
func (p *Proof) Authenticate(r *http.Request) *http.Request {
	authenticated, err := p.AuthenticateStrict(r)
	if err != nil {
		return r
	}
	return authenticated
}

// MarkAuthority preserves the established central-authority forwarding path.
// It must be called only after the authority has authenticated the relay node
// with its dedicated TLS 1.3 client certificate and validated node scope.
func MarkAuthority(r *http.Request) *http.Request {
	forwarded := Forwarded{ClientIP: r.Header.Get(ClientIPHeader), Scheme: "https", Host: r.Host}
	if ValidateMetadata(forwarded) != nil {
		return r
	}
	return withForwarded(r, forwarded)
}

// FromRequest returns metadata authenticated at the panel/authority boundary.
func FromRequest(r *http.Request) (Forwarded, bool) {
	forwarded, ok := r.Context().Value(forwardedContextKey{}).(Forwarded)
	return forwarded, ok
}

type forwardedContextKey struct{}

func withForwarded(r *http.Request, forwarded Forwarded) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), forwardedContextKey{}, forwarded))
}

func singleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func requestDigest(r *http.Request) (string, string, [sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	if r == nil || r.URL == nil || len(r.Method) == 0 || len(r.Method) > maxMethodLen || !httpguts.ValidHeaderFieldName(r.Method) {
		return "", "", empty, ErrInvalidMetadata
	}
	target := r.URL.RequestURI()
	if len(target) == 0 || len(target) > maxRequestTarget {
		return "", "", empty, ErrInvalidMetadata
	}
	if r.ContentLength > MaxBodyBytes {
		return "", "", empty, ErrBodyTooLarge
	}
	digest, err := bodyDigest(r)
	return r.Method, target, digest, err
}

func bodyDigest(r *http.Request) ([sha256.Size]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return sha256.Sum256(nil), nil
	}
	original := r.Body
	raw, err := io.ReadAll(io.LimitReader(original, MaxBodyBytes+1))
	restore := func() {
		r.Body = struct {
			io.Reader
			io.Closer
		}{Reader: io.MultiReader(bytes.NewReader(raw), original), Closer: original}
	}
	if err != nil {
		restore()
		return [sha256.Size]byte{}, errors.New("panel proxy body unavailable")
	}
	if int64(len(raw)) > MaxBodyBytes {
		restore()
		return [sha256.Size]byte{}, ErrBodyTooLarge
	}
	_ = original.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	return sha256.Sum256(raw), nil
}

func (p *Proof) consume(nonce [nonceLen]byte, expires, now int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.used[nonce]; exists {
		return ErrInvalidProof
	}
	if len(p.used) >= maxUsedProofs {
		for value, expiry := range p.used {
			if expiry <= now {
				delete(p.used, value)
			}
		}
		if len(p.used) >= maxUsedProofs {
			return ErrReplayCacheSaturated
		}
	}
	p.used[nonce] = expires
	return nil
}

func (p *Proof) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

func (p *Proof) sum(forwarded Forwarded, method, target string, body [sha256.Size]byte, nonce [nonceLen]byte, expires int64) [sha256.Size]byte {
	mac := hmac.New(sha256.New, p.key[:])
	_, _ = mac.Write([]byte(proofContext))
	for _, value := range []string{forwarded.ClientIP, forwarded.Scheme, forwarded.Host, method, target} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(value))
	}
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(expires))
	_, _ = mac.Write(timestamp[:])
	_, _ = mac.Write(nonce[:])
	_, _ = mac.Write(body[:])
	var out [sha256.Size]byte
	copy(out[:], mac.Sum(nil))
	return out
}
