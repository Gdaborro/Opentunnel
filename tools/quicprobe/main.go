// quicprobe answers "does UDP/443 (QUIC/HTTP3 egress) survive this
// network?" without a QUIC stack: send a long-header Initial with a
// RESERVED version and any compliant QUIC server MUST answer with a
// Version Negotiation packet (RFC 9000 §6.1 — reserved 0x?a?a?a?a
// versions exist precisely for this). No response means the datagram
// was dropped: UDP/443 is blocked or nothing QUIC listens there.
//
// Usage: go run ./tools/quicprobe [host ...]   (defaults below)
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

const reservedVersion = 0x1a2a3a4a // 0x?a?a?a?a: forces Version Negotiation

var defaultHosts = []string{
	"cloudflare-quic.com:443", // canonical public QUIC endpoint
	"google.com:443",          // Google h3
	"dns.google:443",
}

func probe(host string) bool {
	udp, err := net.DialTimeout("udp", host, 3*time.Second)
	if err != nil {
		return false
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))

	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)

	// Long header (0xC0 = Initial type), reserved version, CIDs, then
	// zero padding to the RFC 9000 minimum datagram size (1200) — servers
	// ignore VN-trigger payloads but expect well-formed sizes.
	pkt := make([]byte, 0, 1200)
	pkt = append(pkt, 0xC0)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], reservedVersion)
	pkt = append(pkt, ver[:]...)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, make([]byte, 1200-len(pkt))...)

	if _, err := udp.Write(pkt); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	n, err := udp.Read(buf)
	if err != nil || n < 5 {
		return false
	}
	// Version Negotiation: long header (0x80|) with version 0x00000000.
	if buf[0]&0xC0 == 0x80 {
		var respVer uint32
		if n >= 5 {
			respVer = binary.BigEndian.Uint32(buf[1:5])
		}
		return respVer == 0
	}
	return false
}

func main() {
	hosts := defaultHosts
	if len(os.Args) > 1 {
		hosts = os.Args[1:]
	}
	any := false
	for _, h := range hosts {
		ok := probe(h)
		fmt.Printf("%-24s %s\n", h, map[bool]string{true: "QUIC EGRESS OPEN (VN answered)", false: "no answer (blocked or no listener)"}[ok])
		any = any || ok
	}
	fmt.Println()
	if any {
		fmt.Println("=> UDP/443 survives: an HTTP/3 transport tier would work on this network.")
	} else {
		fmt.Println("=> UDP/443 appears blocked: the QUIC tier would not engage here; SSH remains the only covert bulk path.")
	}
}
