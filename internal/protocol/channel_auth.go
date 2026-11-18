package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
)

// ChannelVersion is an explicit opt-in migration, accepted only inside pinned
// independent TLS 1.3 mutual authentication. The exporter binds possession
// proof to that ephemeral connection; a longer salt cache is not the defense.
const ChannelVersion byte = 6
const channelExporterLabel = "EXPORTER-opentunnel-device-session-v1"

func ChannelBinding(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != InnerTLSALPN || len(cs.PeerCertificates) == 0 {
		return nil, errors.New("connection-bound authentication requires independent mutual TLS 1.3")
	}
	return cs.ExportKeyingMaterial(channelExporterLabel, nil, sha256.Size)
}

func ChannelHandshakeMsg(token string, salt, binding []byte) ([]byte, error) {
	if len(token) < 16 || len(token) > maxTokenLen || len(salt) != SaltSize || len(binding) != sha256.Size {
		return nil, errors.New("invalid connection-bound authentication inputs")
	}
	msg := append([]byte("otu-channel-auth-v1\x00"), binding...)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(token)))
	msg = append(msg, length[:]...)
	msg = append(msg, token...)
	return append(msg, salt...), nil
}

func WriteChannelHandshake(w io.Writer, token string, salt, sig []byte) error {
	if len(token) < 16 || len(token) > maxTokenLen || len(salt) != SaltSize || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid connection-bound authentication message")
	}
	frame := append([]byte(nil), Magic[:]...)
	frame = append(frame, ChannelVersion, byte(len(token)>>8), byte(len(token)))
	frame = append(frame, token...)
	frame = append(frame, salt...)
	frame = append(frame, 0, ed25519.SignatureSize)
	frame = append(frame, sig...)
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}
