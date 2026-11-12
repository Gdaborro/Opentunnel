package protocol

import (
	"bytes"
	"testing"
)

func FuzzHandshakeParser(f *testing.F) {
	f.Add([]byte{'O', 'T', 'U', '1', 5, 0, 0})
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			return
		}
		_, _ = ReadHandshake(bytes.NewReader(data))
	})
}
func FuzzAddressParser(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024 {
			return
		}
		_, _ = ReadAddress(bytes.NewReader(data))
	})
}
