package client

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/privatefile"
	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

type innerTransport struct {
	transport.Transport
	pins [][32]byte
}

func WithInnerTLS(carrier transport.Transport, pins []string) (transport.Transport, error) {
	if len(pins) == 0 {
		return nil, errors.New("inner TLS is enabled without a relay identity pin")
	}
	parsed := make([][32]byte, 0, len(pins))
	for _, value := range pins {
		pin, err := protocol.ParsePublicKeyPin(value)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, pin)
	}
	return &innerTransport{Transport: carrier, pins: parsed}, nil
}

func (t *innerTransport) Dial(ctx context.Context) (net.Conn, error) {
	store, err := NewTokenStore()
	if err != nil {
		return nil, err
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		return nil, err
	}
	if _, err := store.EnsureSSHKey(); err != nil {
		return nil, err
	}
	data, err := privatefile.Read(store.SSHPrivatePath(), 16<<10)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, errors.New("inner TLS device key unavailable")
	}
	var ed ed25519.PrivateKey
	switch key := key.(type) {
	case ed25519.PrivateKey:
		ed = key
	case *ed25519.PrivateKey:
		ed = *key
	default:
		return nil, errors.New("inner TLS device key is not Ed25519")
	}
	cert, err := protocol.DeviceCertificate(device.Token, ed)
	if err != nil {
		return nil, err
	}
	raw, err := t.Transport.Dial(ctx)
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stop := context.AfterFunc(dctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if n, err := raw.Write(protocol.InnerTLSMarker[:]); err != nil || n != 4 {
		_ = raw.Close()
		return nil, errors.New("inner TLS marker write failed")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol.InnerTLSALPN}, SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != protocol.InnerTLSALPN || len(cs.PeerCertificates) == 0 {
				return errors.New("inner TLS negotiation failed")
			}
			got, err := protocol.ParsePublicKeyPin(protocol.PublicKeyPin(cs.PeerCertificates[0]))
			if err != nil {
				return err
			}
			matched := 0
			for _, pin := range t.pins {
				matched |= subtle.ConstantTimeCompare(pin[:], got[:])
			}
			if matched != 1 {
				return errors.New("inner TLS relay identity pin mismatch")
			}
			return nil
		}}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(dctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	// In TLS 1.3 the client can finish its flight before the server has
	// verified the client certificate. Wait for an encrypted confirmation
	// of server-side admission rather than calling that early point ready.
	var confirmed [4]byte
	if _, err := io.ReadFull(conn, confirmed[:]); err != nil || confirmed != protocol.InnerTLSConfirmed {
		_ = raw.Close()
		return nil, errors.New("inner mutual TLS admission was not confirmed")
	}
	if dctx.Err() != nil {
		_ = raw.Close()
		return nil, dctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
