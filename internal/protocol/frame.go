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

func writeStatus(w io.Writer, status byte) error {
	_, err := w.Write([]byte{ProtoVersion, status})
	return err
}

// WriteHandshake sends magic + version + token.
func WriteHandshake(w io.Writer, token string) error {
	if len(token) == 0 || len(token) > maxTokenLen {
		return errors.New("protocol: invalid token length")
	}
	buf := make([]byte, 0, len(Magic)+1+2+len(token))
	buf = append(buf, Magic[:]...)
	buf = append(buf, ProtoVersion)
	lenb := [2]byte{}
	binary.BigEndian.PutUint16(lenb[:], uint16(len(token)))
	buf = append(buf, lenb[:]...)
	buf = append(buf, token...)
	_, err := w.Write(buf)
	return err
}

// ReadAndVerifyHandshake reads the peer handshake and replies with a status.
// Token comparison is constant-time. It returns the error only for transport
// problems; auth failures are reported via the returned status as well as
// written to the wire.
func ReadAndVerifyHandshake(r io.Reader, w io.Writer, expected string) (status byte, err error) {
	magic := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return StatusBadVersion, err
	}
	if string(magic) != string(Magic[:]) {
		_ = writeStatus(w, StatusBadVersion)
		return StatusBadVersion, ErrVersionMismatch
	}
	ver := make([]byte, 1)
	if _, err := io.ReadFull(r, ver); err != nil {
		return StatusBadVersion, err
	}
	if ver[0] != ProtoVersion {
		_ = writeStatus(w, StatusBadVersion)
		return StatusBadVersion, ErrVersionMismatch
	}
	lenb := make([]byte, 2)
	if _, err := io.ReadFull(r, lenb); err != nil {
		return StatusBadToken, err
	}
	n := int(binary.BigEndian.Uint16(lenb))
	if n == 0 || n > maxTokenLen {
		_ = writeStatus(w, StatusBadToken)
		return StatusBadToken, ErrBadToken
	}
	token := make([]byte, n)
	if _, err := io.ReadFull(r, token); err != nil {
		return StatusBadToken, err
	}
	if subtle.ConstantTimeCompare(token, []byte(expected)) != 1 {
		_ = writeStatus(w, StatusBadToken)
		return StatusBadToken, ErrBadToken
	}
	if err := writeStatus(w, StatusOK); err != nil {
		return StatusOK, err
	}
	return StatusOK, nil
}

func ReadAuthResponse(r io.Reader) error {
	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return err
	}
	if resp[0] != ProtoVersion {
		return ErrVersionMismatch
	}
	switch resp[1] {
	case StatusOK:
		return nil
	default:
		return fmt.Errorf("protocol: server rejected handshake (status=%d)", resp[1])
	}
}

// WriteTarget writes the CONNECT-style request address.
func WriteTarget(w io.Writer, a *Address) error { return a.Encode(w) }

func ReadTarget(r io.Reader) (*Address, error) { return ReadAddress(r) }

func WriteTargetResponse(w io.Writer, status byte) error {
	_, err := w.Write([]byte{ProtoVersion, status})
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
	if resp[0] != ProtoVersion {
		return ErrVersionMismatch
	}
	if resp[1] != StatusOK {
		return &StatusError{Status: resp[1]}
	}
	return nil
}
