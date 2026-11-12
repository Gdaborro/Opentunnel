package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"opentunnel/internal/protocol"
)

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (o *Options) innerTLS(stream net.Conn) (net.Conn, string, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return nil, "", err
	}
	if prefix != protocol.InnerTLSMarker {
		if o.RequireInnerTLS {
			return nil, "", errors.New("inner TLS is required")
		}
		return &prefixConn{Conn: stream, r: io.MultiReader(bytes.NewReader(prefix[:]), stream)}, "", nil
	}
	if o.InnerTLSCertificate == nil || o.PanelDB == nil {
		return nil, "", errors.New("inner TLS is not provisioned")
	}
	var token string
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*o.InnerTLSCertificate}, ClientAuth: tls.RequireAnyClientCert, NextProtos: []string{protocol.InnerTLSALPN}, SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != protocol.InnerTLSALPN || len(cs.PeerCertificates) != 1 {
				return errors.New("inner TLS device certificate required")
			}
			cert := cs.PeerCertificates[0]
			if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("inner TLS device credential expired")
			}
			presented, err := protocol.InnerTLSToken(cert)
			if err != nil {
				return err
			}
			p, err := o.readPolicy(presented)
			if err != nil || (p.Status != "approved" && p.Status != "kicked") {
				return errors.New("inner TLS admission denied")
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.PublicKey))
			if err != nil {
				return errors.New("inner TLS enrolled key unavailable")
			}
			cryptoKey, ok := pub.(ssh.CryptoPublicKey)
			if !ok {
				return errors.New("invalid enrolled key")
			}
			enrolled, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
			if !ok {
				return errors.New("inner TLS requires Ed25519")
			}
			actual, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok || subtle.ConstantTimeCompare(actual, enrolled) != 1 {
				return errors.New("inner TLS device key mismatch")
			}
			token = presented
			o.innerGeneration, o.innerPublicKey = p.Generation, p.PublicKey
			return nil
		}}
	conn := tls.Server(stream, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), o.setupTimeout())
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, "", err
	}
	if _, err := conn.Write(protocol.InnerTLSConfirmed[:]); err != nil {
		return nil, "", err
	}
	return conn, token, nil
}
