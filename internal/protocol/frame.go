package protocol

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const maxTokenLen = 256

var ErrVersionMismatch = errors.New("protocol: version mismatch")
var ErrBadToken = errors.New("protocol: authentication failed")

type AuthStatus byte

// AuthError reports a non-OK handshake status (pending, banned, expired…).
type AuthError struct{ Status byte }

func (e *AuthError) Error() string {
	return fmt.Sprintf("protocol: server rejected handshake (status=%d)", e.Status)
}

// writeStatus echoes the SESSION's version so pre-v5 clients (whose
// response parser checks the version byte) keep working against new
// servers; any verdict we must deliver before knowing the version (bad
// magic) uses the current version.
func writeStatus(w io.Writer, ver, status byte) error {
	_, err := w.Write([]byte{ver, status})
	return err
}

// WriteHandshakeStatus is the server's handshake verdict (version echo).
func WriteHandshakeStatus(w io.Writer, ver, status byte) error {
	return writeStatus(w, ver, status)
}

// WriteHandshake sends the v4 handshake: magic + version + token.
func WriteHandshake(w io.Writer, token string) error {
	if len(token) == 0 || len(token) > maxTokenLen {
		return errors.New("protocol: invalid token length")
	}
	buf := make([]byte, 0, len(Magic)+1+2+len(token))
	buf = append(buf, Magic[:]...)
	buf = append(buf, ProtoVersionLegacy)
	lenb := [2]byte{}
	binary.BigEndian.PutUint16(lenb[:], uint16(len(token)))
	buf = append(buf, lenb[:]...)
	buf = append(buf, token...)
	_, err := w.Write(buf)
	return err
}

// HandshakeMsg builds the exact bytes a v5 handshake signature covers:
// a fixed domain-separation prefix, the length-prefixed token, and the
// session salt. Binding the salt per session makes captured handshakes
// non-replayable under the relay's salt cache.
func HandshakeMsg(token string, salt []byte) []byte {
	msg := make([]byte, 0, 17+2+len(token)+len(salt))
	msg = append(msg, "otu-handshake-v1:"...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(token)))
	msg = append(msg, lb[:]...)
	msg = append(msg, token...)
	msg = append(msg, salt...)
	return msg
}

// WriteHandshakeV5 sends magic + version 5 + token + salt + signature.
func WriteHandshakeV5(w io.Writer, token string, salt, sig []byte) error {
	if len(token) == 0 || len(token) > maxTokenLen {
		return errors.New("protocol: invalid token length")
	}
	if len(salt) != SaltSize {
		return errors.New("protocol: invalid salt length")
	}
	buf := make([]byte, 0, len(Magic)+1+2+len(token)+SaltSize+2+len(sig))
	buf = append(buf, Magic[:]...)
	buf = append(buf, ProtoVersion)
	lenb := [2]byte{}
	binary.BigEndian.PutUint16(lenb[:], uint16(len(token)))
	buf = append(buf, lenb[:]...)
	buf = append(buf, token...)
	buf = append(buf, salt...)
	binary.BigEndian.PutUint16(lenb[:], uint16(len(sig)))
	buf = append(buf, lenb[:]...)
	buf = append(buf, sig...)
	_, err := w.Write(buf)
	return err
}

// Handshake is the parsed client hello (version 4 or 5).
type Handshake struct {
	Version byte
	Token   string
	Salt    []byte // v5 only: session salt carried inside the handshake
	Sig     []byte // v5 only: Ed25519 over HandshakeMsg(Token, Salt)
}

// ReadHandshake parses a client handshake without applying any policy.
// Version 4 leaves Salt/Sig nil (the salt arrives separately, as always).
func ReadHandshake(r io.Reader) (*Handshake, error) {
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	if string(magic) != string(Magic[:]) {
		return nil, ErrVersionMismatch
	}
	ver := make([]byte, 1)
	if _, err := io.ReadFull(r, ver); err != nil {
		return nil, err
	}
	if ver[0] != ProtoVersion && ver[0] != ProtoVersionLegacy {
		return nil, ErrVersionMismatch
	}
	lenb := make([]byte, 2)
	if _, err := io.ReadFull(r, lenb); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenb))
	if n == 0 || n > maxTokenLen {
		return nil, ErrBadToken
	}
	tok := make([]byte, n)
	if _, err := io.ReadFull(r, tok); err != nil {
		return nil, err
	}
	hs := &Handshake{Version: ver[0], Token: string(tok)}
	if ver[0] == ProtoVersion {
		hs.Salt = make([]byte, SaltSize)
		if _, err := io.ReadFull(r, hs.Salt); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, lenb); err != nil {
			return nil, err
		}
		sn := int(binary.BigEndian.Uint16(lenb))
		if sn == 0 || sn > 128 {
			return nil, ErrBadToken
		}
		hs.Sig = make([]byte, sn)
		if _, err := io.ReadFull(r, hs.Sig); err != nil {
			return nil, err
		}
	}
	return hs, nil
}

// StaticVerifier returns a verify func that constant-time compares the
// presented token against one static secret (legacy/no-panel mode).
func StaticVerifier(expected string) func(string) byte {
	return func(token string) byte {
		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {
			return StatusOK
		}
		return StatusBadToken
	}
}

func ReadAuthResponse(r io.Reader) error {
	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return err
	}
	if resp[0] != ProtoVersion && resp[0] != ProtoVersionLegacy {
		return ErrVersionMismatch
	}
	switch resp[1] {
	case StatusOK:
		return nil
	default:
		return &AuthError{Status: resp[1]}
	}
}

// ReadHandshakeStatus reads the server's 2-byte handshake verdict and
// returns its version echo alongside the status, so a v5 client can
// distinguish "legacy server, retry as v4" from a real verdict.
func ReadHandshakeStatus(r io.Reader) (ver, status byte, err error) {
	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return 0, 0, err
	}
	return resp[0], resp[1], nil
}

// ReadAndVerifyHandshake is the token-policy convenience wrapper used by
// tests and legacy flows: parses either handshake version, applies verify,
// echoes the session version, and returns the token. v5 signature
// verification lives in the relay (it needs the key store), so a v5 hello
// passing through here has its salt/sig consumed without checking.
func ReadAndVerifyHandshake(r io.Reader, w io.Writer, verify func(token string) byte) (byte, string, error) {
	hs, herr := ReadHandshake(r)
	if herr != nil {
		st := byte(StatusBadVersion)
		if errors.Is(herr, ErrBadToken) {
			st = StatusBadToken
		}
		if !errors.Is(herr, io.EOF) && !errors.Is(herr, io.ErrUnexpectedEOF) {
			_ = writeStatus(w, ProtoVersion, st)
		}
		return st, "", herr
	}
	st := verify(hs.Token)
	_ = writeStatus(w, hs.Version, st)
	if st == StatusBadToken {
		return st, "", ErrBadToken
	}
	if st != StatusOK {
		return st, "", nil
	}
	return StatusOK, hs.Token, nil
}

// WriteTarget writes the CONNECT-style request address.
func WriteTarget(w io.Writer, a *Address) error { return a.Encode(w) }

func ReadTarget(r io.Reader) (*Address, error) { return ReadAddress(r) }

// WriteTargetResponse echoes the session version like handshake verdicts.
func WriteTargetResponse(w io.Writer, ver, status byte) error {
	if ver == 0 {
		ver = ProtoVersion
	}
	_, err := w.Write([]byte{ver, status})
	return err
}

// StatusError reports a nonzero target-connect status from the server.
type StatusError struct{ Status byte }

func (e *StatusError) Error() string {
	return fmt.Sprintf("protocol: connect failed (status=%d)", e.Status)
}

func ReadTargetResponse(r io.Reader) error {
	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return err
	}
	if resp[0] != ProtoVersion && resp[0] != ProtoVersionLegacy {
		return ErrVersionMismatch
	}
	if resp[1] != StatusOK {
		return &StatusError{Status: resp[1]}
	}
	return nil
}
