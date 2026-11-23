package authority

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

func nodeForCertificate(nodes Nodes, cert *x509.Certificate) (string, error) {
	if cert == nil || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) || cert.IsCA {
		return "", errors.New("authority node certificate expired or invalid")
	}
	pin := protocol.PublicKeyPin(cert)
	for _, node := range nodes.Nodes {
		for _, accepted := range node.Pins {
			if subtle.ConstantTimeCompare([]byte(pin), []byte(accepted)) == 1 {
				return node.ID, nil
			}
		}
	}
	return "", errors.New("node credential not in the authority's explicit inventory")
}

func ServerTLS(certificate tls.Certificate, nodes Nodes) (*tls.Config, error) {
	if err := nodes.Validate(); err != nil {
		return nil, err
	}
	if len(certificate.Certificate) != 1 {
		return nil, errors.New("authority TLS needs a dedicated single-certificate identity")
	}
	serverCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	serverPin := protocol.PublicKeyPin(serverCert)
	for _, node := range nodes.Nodes {
		for _, pin := range node.Pins {
			if pin == serverPin {
				return nil, errors.New("authority and relay TLS keys must be separate")
			}
		}
	}
	owned := Nodes{Nodes: make([]Node, len(nodes.Nodes))}
	for i, n := range nodes.Nodes {
		owned.Nodes[i] = Node{ID: n.ID, Pins: append([]string(nil), n.Pins...)}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true, NextProtos: []string{"h2", "http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version != tls.VersionTLS13 || len(cs.PeerCertificates) != 1 {
				return errors.New("authority requires a dedicated node TLS 1.3 identity")
			}
			_, err := nodeForCertificate(owned, cs.PeerCertificates[0])
			return err
		}}, nil
}

func ClientTLS(certificate tls.Certificate, serverName string, pins []string) (*tls.Config, error) {
	if len(pins) < 1 || len(pins) > 2 {
		return nil, errors.New("authority TLS needs explicit public-key pin(s)")
	}
	for _, pin := range pins {
		if !serverpool.ValidID(pin) {
			return nil, errors.New("invalid authority public-key pin")
		}
	}
	if len(certificate.Certificate) != 1 {
		return nil, errors.New("relay needs a dedicated node certificate")
	}
	nodeCert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	nodePin := protocol.PublicKeyPin(nodeCert)
	for _, pin := range pins {
		if pin == nodePin {
			return nil, errors.New("node and authority credentials cannot share a key")
		}
	}
	owned := append([]string(nil), pins...)
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: serverName, Certificates: []tls.Certificate{certificate}, InsecureSkipVerify: true, SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version != tls.VersionTLS13 || len(cs.PeerCertificates) != 1 {
				return errors.New("authority TLS identity required")
			}
			cert := cs.PeerCertificates[0]
			if now := time.Now(); now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.IsCA {
				return errors.New("authority TLS identity expired")
			}
			got := protocol.PublicKeyPin(cert)
			for _, pin := range owned {
				if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) == 1 {
					return nil
				}
			}
			return errors.New("authority TLS public-key pin mismatch")
		}}, nil
}
