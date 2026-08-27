package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

func WriteToken(w io.Writer, token string) error {
	if len(token) > 1024 {
		return fmt.Errorf("token too long")
	}
	l := uint16(len(token))
	if err := binary.Write(w, binary.BigEndian, l); err != nil {
		return err
	}
	_, err := w.Write([]byte(token))
	return err
}

func ReadToken(r io.Reader) (string, error) {
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return "", err
	}
	if l == 0 || l > 1024 {
		return "", fmt.Errorf("invalid token length %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
