package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/xtaci/smux"
)

// MuxConfig returns the smux parameters used on both ends of a tunnel so
// buffer sizes and keepalives always match.
func MuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.KeepAliveTimeout = 40 * time.Second
	cfg.MaxFrameSize = 16384
	cfg.MaxReceiveBuffer = 4 * 1024 * 1024
	cfg.MaxStreamBuffer = 2 * 1024 * 1024
	return cfg
}

// WriteUDPFrame emits one datagram frame:
//
//	[u16 total][ATYP][addr][port][payload]
//
// where "total" covers the address bytes plus payload.
func WriteUDPFrame(w io.Writer, dst *Address, payload []byte) error {
	if len(payload) > 0xFFFF {
		return fmt.Errorf("protocol: udp payload too large: %d", len(payload))
	}
	var abuf bytes.Buffer
	if err := dst.Encode(&abuf); err != nil {
		return err
	}
	total := abuf.Len() + len(payload)
	if total > 0xFFFF {
		return fmt.Errorf("protocol: udp frame too large")
	}
	out := make([]byte, 2, 2+total)
	binary.BigEndian.PutUint16(out[:2], uint16(total))
	out = append(out, abuf.Bytes()...)
	out = append(out, payload...)
	_, err := w.Write(out)
	return err
}

// ReadUDPFrame parses one datagram frame written by WriteUDPFrame.
func ReadUDPFrame(r io.Reader) (*Address, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, nil, err
	}
	total := binary.BigEndian.Uint16(hdr)
	if total < 2 {
		return nil, nil, fmt.Errorf("protocol: udp frame too short")
	}
	body := make([]byte, total)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	br := bytes.NewReader(body)
	atyp := make([]byte, 1)
	if _, err := br.Read(atyp); err != nil {
		return nil, nil, err
	}
	dst, err := ReadAddressWithATYP(atyp[0], br)
	if err != nil {
		return nil, nil, err
	}
	payload := make([]byte, br.Len())
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, nil, err
	}
	return dst, payload, nil
}
