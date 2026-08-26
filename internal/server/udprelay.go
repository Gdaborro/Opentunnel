package server

import (
	"io"
	"log"
	"net"

	"opentunnel/internal/protocol"
)

// serveUDPStream relays UDP datagrams between one mux stream and the
// internet. Each datagram frame carries its destination (upstream) or source
// (downstream) address, so no NAT table is needed:
//
//	client → server: [u16][ATYP addr port][payload]  (destination)
//	server → client: [u16][ATYP addr port][payload]  (source)
func serveUDPStream(rw io.ReadWriteCloser, logger *log.Logger) {
	defer rw.Close()

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		logger.Printf("server: udp relay listen: %v", err)
		return
	}
	defer pc.Close()

	// Socket → client.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			src := udpAddrToAddress(from)
			if src == nil {
				continue
			}
			if err := protocol.WriteUDPFrame(rw, src, buf[:n]); err != nil {
				return
			}
		}
	}()

	for {
		dst, payload, err := protocol.ReadUDPFrame(rw)
		if err != nil {
			return
		}
		raddr, err := net.ResolveUDPAddr("udp", dst.HostPort())
		if err != nil {
			continue
		}
		if _, err := pc.WriteTo(payload, raddr); err != nil {
			if _, ok := err.(net.Error); !ok {
				return
			}
		}
	}
}

// udpAddrToAddress converts a *net.UDPAddr into our wire Address type.
func udpAddrToAddress(from net.Addr) *protocol.Address {
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return nil
	}
	if ip4 := ua.IP.To4(); ip4 != nil {
		return &protocol.Address{Type: protocol.ATypIPv4, IP: ip4, Port: uint16(ua.Port)}
	}
	return &protocol.Address{Type: protocol.ATypIPv6, IP: ua.IP, Port: uint16(ua.Port)}
}
