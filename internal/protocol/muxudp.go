package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/xtaci/smux"
)

// MuxConfig returns the smux parameters used on both ends of a tunnel so
// buffer sizes and keepalives always match. Windows are sized for high-BDP
// paths: throughput <= buffer / RTT, so 8 MB stream buffers sustain
// hundreds of Mbps even at ~150 ms RTT.
//
// Keepalives are deliberately jittered per session (per call): a fixed
// 20 s NOP on every idle session is a fleet-wide correlation signature at
// the flow level — many devices beating in lockstep. A randomized idle
// cadence (20–35 s) with a receive-silence timeout comfortably above the
// PEER's widest cadence reads as ordinary application heartbeat traffic.
func MuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	interval := 20*time.Second + time.Duration(rand.Int63n(int64(15*time.Second)))
	cfg.KeepAliveInterval = interval
	cfg.KeepAliveTimeout = interval + 30*time.Second + time.Duration(rand.Int63n(int64(15*time.Second)))
	cfg.MaxFrameSize = 32768
	cfg.MaxReceiveBuffer = 16 * 1024 * 1024
	cfg.MaxStreamBuffer = 8 * 1024 * 1024
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
