// tlsprobe tests which TLS client fingerprints reach a server unmolested
// from the current network. For each identity it reports the certificate
// issuer actually received — Let's Encrypt means clean passage; anything
// else means interception.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	utls "github.com/refraction-networking/utls"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: tlsprobe host:port sni-hostname")
		os.Exit(1)
	}
	addr := os.Args[1]
	server := os.Args[2]

	run := func(name string, f func() ([]*x509.Certificate, error)) {
		certs, err := f()
		if err != nil {
			fmt.Printf("%-22s FAIL  %v\n", name, err)
			return
		}
		if len(certs) == 0 {
			fmt.Printf("%-22s ?     no certs\n", name)
			return
		}
		org := "unknown"
		if len(certs[0].Issuer.Organization) > 0 {
			org = certs[0].Issuer.Organization[0]
		}
		cn := certs[0].Subject.CommonName
		fmt.Printf("%-22s issuer=%-28s CN=%s\n", name, org, cn)
	}

	std := func(next bool) func() ([]*x509.Certificate, error) {
		return func() ([]*x509.Certificate, error) {
			cfg := &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         server,
				MinVersion:         tls.VersionTLS12,
				NextProtos:         []string{"h2", "http/1.1"},
				// next=false -> no ALPN at all
			}
			if !next {
				cfg.NextProtos = nil
			}
			c, err := tls.Dial("tcp", addr, cfg)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			return c.ConnectionState().PeerCertificates, nil
		}
	}

	u := func(id utls.ClientHelloID) func() ([]*x509.Certificate, error) {
		return func() ([]*x509.Certificate, error) {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			cfg := &utls.Config{InsecureSkipVerify: true, ServerName: server}
			c := utls.UClient(raw, cfg, id)
			if err := c.Handshake(); err != nil {
				raw.Close()
				return nil, err
			}
			defer c.Close()
			return c.ConnectionState().PeerCertificates, nil
		}
	}

	run("go-default+alpn", std(true))
	run("go-default-noalpn", std(false))
	run("chrome_auto(uTLS)", u(utls.HelloChrome_Auto))
	run("firefox_auto(uTLS)", u(utls.HelloFirefox_Auto))
	run("ios_auto(uTLS)", u(utls.HelloIOS_Auto))
	run("edge_auto(uTLS)", u(utls.HelloEdge_Auto))
	run("randomized(uTLS)", u(utls.HelloRandomizedALPN))
	run("hello360(uTLS)", u(utls.Hello360_Auto))
	run("qq_browser(uTLS)", u(utls.HelloQQ_Auto))
	run("safari(uTLS)", u(utls.HelloSafari_Auto))
}
