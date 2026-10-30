// control.go: the in-band control channel (v0.9.23). Status and health
// telemetry ride a dedicated stream inside the authenticated mux session
// instead of HTTPS: on TLS-intercepting networks (school/enterprise MITM)
// pinned HTTPS cannot connect by design, and the panel would otherwise
// never hear from those devices. Inside the session the traffic is already
// AEAD-encrypted end to end — invisible to the middlebox, no new flows.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// CtrlMarker is the first byte of a control stream (protocol v5 streams:
// MuxMarker sessions carry per-stream markers: UdpMarker, CtrlMarker, or
// an ATYP byte for single-target relays).
const CtrlMarker byte = 0x43 // 'C'

// CtrlRequest is a control-channel request. Status polls carry just the
// token; health reports add the telemetry fields (mirrors the panel's
// /api/token/health payload).
type CtrlRequest struct {
	Op    string `json:"op"` // "status" | "health"
	Token string `json:"token"`

	Version      string  `json:"version,omitempty"`
	OS           string  `json:"os,omitempty"`
	Arch         string  `json:"arch,omitempty"`
	CPUPct       float64 `json:"cpu_pct,omitempty"`
	MemPct       float64 `json:"mem_pct,omitempty"`
	TempC        float64 `json:"temp_c,omitempty"`
	UptimeS      int64   `json:"uptime_s,omitempty"`
	LatencyMs    float64 `json:"latency_ms,omitempty"`
	JitterMs     float64 `json:"jitter_ms,omitempty"`
	ProbeLossPct float64 `json:"probe_loss_pct,omitempty"`
}

// CtrlResponse answers a control request. Pin carries the relay's CURRENT
// leaf certificate fingerprint so clients survive certificate rotation:
// the HTTPS pin is the credential's anchor, and LE renews the leaf every
// ~60-90 days — without this, every renewal bricks every pinned client.
// The field is authoritative only because the channel itself is
// authenticated by the device token end to end; a MITM cannot complete a
// session and therefore cannot inject a pin.
type CtrlResponse struct {
	OK          bool   `json:"ok"`
	Status      string `json:"status"`
	KickReason  string `json:"kick_reason"`
	BanReason   string `json:"ban_reason"`
	KickExpires string `json:"kick_expires"`
	Pin         string `json:"pin"`
	// SSHHost, when set, is the relay's public ssh-tier dial target — a
	// plain A record a CDN front does not proxy (port 22). Clients learn
	// and persist it in-band so the ssh last-resort tier keeps a dialable
	// target after the tunnel domain moves behind a CDN, without any
	// per-device config update. Injection is impossible from outside: the
	// control channel lives inside the authenticated, AEAD-sealed session.
	SSHHost string `json:"ssh_host,omitempty"`
}

// WriteCtrlMessage frames v as [u16 length][JSON].
func WriteCtrlMessage(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > 65535 {
		return errors.New("protocol: control message too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ReadCtrlMessage reads a [u16 length][JSON] frame into v.
func ReadCtrlMessage(r io.Reader, v any) error {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}
