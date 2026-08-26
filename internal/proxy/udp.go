package proxy

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"

	"opentunnel/internal/protocol"
)

// handleUDPAssociate implements SOCKS5 CMD=3 on the control TCP connection:
// it opens a loopback UDP socket, tells the client its address, and pumps
// datagrams through the tunnel's framed UDP relay until the TCP control
// connection closes.
func handleUDPAssociate(ctx context.Context, ctrl net.Conn, ud UDPDialer, logErr *log.Logger) {
	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		if logErr != nil {
			logErr.Printf("socks-udp: listen: %v", err)
		}
		_, _ = ctrl.Write([]byte{socksVer, 0x01, 0x00})
		return
	}
	defer udpSock.Close()

	// Reply: BND.ADDR = 127.0.0.1, BND.PORT = udp port.
	port := udpSock.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{socksVer, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if _, err := ctrl.Write(reply); err != nil {
		return
	}

	relay, err := ud.OpenUDPRelay(ctx)
	if err != nil {
		if logErr != nil {
			logErr.Printf("socks-udp: relay open: %v", err)
		}
		return
	}
	defer relay.Close()

	// Track the single app using this association (typical SOCKS5 usage).
	var lastClient *net.UDPAddr
	var mu chan struct{} = make(chan struct{}, 1) // binary semaphore

	// App → tunnel.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udpSock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu <- struct{}{}
			lastClient = from
			<-mu

			dst, payload, err := parseSocksUDPHeader(buf[:n])
			if err != nil {
				continue // drop malformed (FRAG unsupported etc.)
			}
			if err := protocol.WriteUDPFrame(relay, dst, payload); err != nil {
				return
			}
		}
	}()

	// Tunnel → app.
	for {
		src, payload, err := protocol.ReadUDPFrame(relay)
		if err != nil {
			return
		}
		mu <- struct{}{}
		dst := lastClient
		<-mu
		if dst == nil {
			continue
		}
		out := make([]byte, 0, 10+len(payload))
		out = append(out, 0, 0, 0) // RSV + FRAG=0
		var abuf bytes.Buffer
		if err := src.Encode(&abuf); err != nil {
			continue
		}
		out = append(out, abuf.Bytes()...)
		out = append(out, payload...)
		if _, err := udpSock.WriteToUDP(out, dst); err != nil && logErr != nil {
			logErr.Printf("socks-udp: writeto: %v", err)
		}
	}
}

// parseSocksUDPHeader strips [RSV u16][FRAG u8] then reads our Address.
func parseSocksUDPHeader(dgram []byte) (*protocol.Address, []byte, error) {
	if len(dgram) < 4 {
		return nil, nil, io.ErrShortBuffer
	}
	frag := dgram[2]
	if frag != 0 {
		return nil, nil, errFragmentationUnsupported
	}
	r := bytes.NewReader(dgram[3:])
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return nil, nil, err
	}
	addr, err := protocol.ReadAddressWithATYP(atyp[0], r)
	if err != nil {
		return nil, nil, err
	}
	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	return addr, payload, nil
}

var errFragmentationUnsupported = &constError{"socks-udp: fragmentation unsupported"}

type constError struct{ s string }

func (e *constError) Error() string { return e.s }
