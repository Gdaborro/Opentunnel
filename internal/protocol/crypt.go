package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"sync"
	"time"
)

// Protocol v2 adds an inner AEAD layer beneath TLS:
//   - keys derived via HKDF-SHA256(token, per-session random salt)
//   - AES-256-GCM (hardware accelerated; ~GB/s, negligible vs network)
//   - direction-separated nonce counters prevent nonce reuse
//   - optional size-bucket padding and write jitter blur traffic shape
//
// The auth token check happens BEFORE any decryption, so unauthenticated
// active probes are answered by the decoy site exactly as in v1.

const (
	SaltSize = 16
	KeySize  = 32

	maxPlaintext  = 16384 + 2 + 512 // payload + length prefix + worst padding
	maxCiphertext = maxPlaintext + 16 + 4

	dirClientToServer byte = 0
	dirServerToClient byte = 1
)

var ErrSaltReplay = errors.New("protocol: session salt replay detected")

// DeriveKeys derives independent AEAD keys for each direction from the shared
// token and a fresh per-session salt.
func DeriveKeys(token string, salt []byte) (clientKey, serverKey []byte, err error) {
	if len(salt) != SaltSize {
		return nil, nil, fmt.Errorf("protocol: salt must be %d bytes", SaltSize)
	}
	ok, err := hkdf.Key(sha256.New, []byte(token), salt, "opentunnel-v2", KeySize*2)
	if err != nil {
		return nil, nil, err
	}
	return ok[:KeySize], ok[KeySize:], nil
}

// RandomSalt returns a cryptographically random session salt.
func RandomSalt() []byte {
	s := make([]byte, SaltSize)
	if _, err := rand.Read(s); err != nil {
		panic("protocol: entropy unavailable: " + err.Error())
	}
	return s
}

// ProfileParams tunes traffic-shaping for the writing side of a stream.
type ProfileParams struct {
	Padding   bool          // pad frames to size buckets
	MaxJitter time.Duration // random delay added before each frame write
}

// ProfilesFor returns the shaping parameters for named profile.
// Unknown names map to Fast (no shaping overhead).
func ProfileFor(name string) ProfileParams {
	switch name {
	case "balanced":
		return ProfileParams{Padding: true}
	case "stealth":
		return ProfileParams{Padding: true, MaxJitter: 20 * time.Millisecond}
	default: // "fast"
		return ProfileParams{}
	}
}

type countedAEAD struct {
	aead    cipher.AEAD
	dir     byte
	counter uint64
	mu      sync.Mutex // guards counter; allows defensive concurrent writers
}

func newCountedAEAD(key []byte, dir byte) (*countedAEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &countedAEAD{aead: a, dir: dir}, nil
}

func (c *countedAEAD) nonce() []byte {
	c.mu.Lock()
	n := make([]byte, 12)
	n[0] = c.dir
	binary.BigEndian.PutUint64(n[4:], c.counter)
	c.counter++
	c.mu.Unlock()
	return n
}

// SecureStream is an io.ReadWriteCloser over a transport stream. Every byte
// crosses the wire inside an AEAD frame:
//
//	[u32 ciphertext length][AES-GCM ciphertext || tag]
//	where plaintext = [u16 payload length][payload][zero padding]
type SecureStream struct {
	conn   net.Conn
	enc    *countedAEAD
	dec    *countedAEAD
	params ProfileParams

	rbuf []byte // decrypted-but-unconsumed payload
}

func newSecureStream(conn net.Conn, sendKey, recvKey []byte, sendDir byte, params ProfileParams) (*SecureStream, error) {
	enc, err := newCountedAEAD(sendKey, sendDir)
	if err != nil {
		return nil, err
	}
	recvDir := dirServerToClient
	if sendDir == dirServerToClient {
		recvDir = dirClientToServer
	}
	dec, err := newCountedAEAD(recvKey, recvDir)
	if err != nil {
		return nil, err
	}
	return &SecureStream{conn: conn, enc: enc, dec: dec, params: params}, nil
}

// ClientSideSecureStream builds the client end (seals with clientKey).
func ClientSideSecureStream(conn net.Conn, token string, salt []byte, params ProfileParams) (*SecureStream, error) {
	ck, sk, err := DeriveKeys(token, salt)
	if err != nil {
		return nil, err
	}
	return newSecureStream(conn, ck, sk, dirClientToServer, params)
}

// ServerSideSecureStream builds the server end (seals with serverKey).
func ServerSideSecureStream(conn net.Conn, token string, salt []byte) (*SecureStream, error) {
	ck, sk, err := DeriveKeys(token, salt)
	if err != nil {
		return nil, err
	}
	return newSecureStream(conn, sk, ck, dirServerToClient, ProfileParams{})
}

func (s *SecureStream) padLen(payload int) int {
	if !s.params.Padding {
		return 0
	}
	total := payload + 2
	for _, b := range [...]int{64, 256, 1024, 4096, 16384} {
		if total <= b {
			jitter := b / 8
			pad := mathrand.Intn(jitter + 1)
			if total+pad <= maxPlaintext-2 {
				return pad
			}
			return 0
		}
	}
	return mathrand.Intn(65)
}

// frameBufPool recycles ciphertext scratch buffers across frames.
var frameBufPool = sync.Pool{
	New: func() any { return make([]byte, 0, maxCiphertext) },
}

func (s *SecureStream) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		chunk := p[written:]
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		if s.params.MaxJitter > 0 {
			time.Sleep(time.Duration(mathrand.Int63n(int64(s.params.MaxJitter) + 1)))
		}
		plain := make([]byte, 2+len(chunk)+s.padLen(len(chunk)))
		binary.BigEndian.PutUint16(plain[:2], uint16(len(chunk)))
		copy(plain[2:], chunk)
		nonce := s.enc.nonce()

		buf := frameBufPool.Get().([]byte)
		ct := s.enc.aead.Seal(buf[:0], nonce, plain, nil)
		frame := make([]byte, 4+len(ct))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(ct)))
		copy(frame[4:], ct)
		frameBufPool.Put(buf[:0])

		// Single transport write per frame: fewer records, steadier shape.
		if _, err := s.conn.Write(frame); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

func (s *SecureStream) Read(p []byte) (int, error) {
	if len(s.rbuf) > 0 {
		n := copy(p, s.rbuf)
		s.rbuf = s.rbuf[n:]
		return n, nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(s.conn, hdr); err != nil {
		return 0, err
	}
	ctLen := binary.BigEndian.Uint32(hdr)
	if ctLen < 18 || ctLen > maxCiphertext {
		return 0, fmt.Errorf("protocol: corrupt frame length %d", ctLen)
	}
	buf := frameBufPool.Get().([]byte)
	ct := buf[:0]
	if cap(ct) < int(ctLen) {
		ct = make([]byte, 0, ctLen)
	}
	ct = ct[:ctLen]
	if _, err := io.ReadFull(s.conn, ct); err != nil {
		frameBufPool.Put(buf[:0])
		return 0, err
	}
	plain, err := s.dec.aead.Open(nil, s.dec.nonce(), ct, nil)
	frameBufPool.Put(buf[:0])
	if err != nil {
		return 0, fmt.Errorf("protocol: decrypt failed (tamper or desync): %w", err)
	}
	if len(plain) < 2 {
		return 0, errors.New("protocol: short frame")
	}
	realLen := int(binary.BigEndian.Uint16(plain[:2]))
	if realLen > len(plain)-2 {
		return 0, errors.New("protocol: payload exceeds frame")
	}
	payload := plain[2 : 2+realLen]
	n := copy(p, payload)
	s.rbuf = append(s.rbuf[:0], payload[n:]...)
	return n, nil
}

func (s *SecureStream) Close() error                       { return s.conn.Close() }
func (s *SecureStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *SecureStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *SecureStream) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *SecureStream) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *SecureStream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// ReplayCache remembers session salts to defeat record-and-replay probing.
type ReplayCache struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
	cap int
}

func NewReplayCache(ttl time.Duration, capacity int) *ReplayCache {
	return &ReplayCache{m: make(map[string]time.Time), ttl: ttl, cap: capacity}
}

// CheckAndAdd reports whether the salt is fresh; it records it either way.
func (rc *ReplayCache) CheckAndAdd(salt []byte) bool {
	key := string(salt)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	now := time.Now()
	if len(rc.m) >= rc.cap {
		// Cheap reset: TTL sweep on overflow.
		for k, ts := range rc.m {
			if now.Sub(ts) > rc.ttl {
				delete(rc.m, k)
			}
		}
		if len(rc.m) >= rc.cap {
			rc.m = make(map[string]time.Time)
		}
	}
	if ts, ok := rc.m[key]; ok && now.Sub(ts) <= rc.ttl {
		return false
	}
	rc.m[key] = now
	return true
}

// WriteSalt sends the session salt (plaintext; TLS already covers it and the
// contents are public by design — freshness is what matters).
func WriteSalt(w io.Writer, salt []byte) error {
	if len(salt) != SaltSize {
		return fmt.Errorf("protocol: bad salt size %d", len(salt))
	}
	_, err := w.Write(salt)
	return err
}

// ReadSalt reads the peer's session salt.
func ReadSalt(r io.Reader) ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, err
	}
	return salt, nil
}
