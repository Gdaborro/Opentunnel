package proxy

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"sync"

	"opentunnel/internal/protocol"
)

// handleUDPAssociate implements SOCKS5 CMD=3 on the control TCP connection:
// it opens a loopback UDP socket, tells the client its address, and pumps
// datagrams through the tunnel's framed UDP relay until the TCP control
// connection closes.
func handleUDPAssociate(ctx context.Context, ctrl net.Conn, ud UDPDialer, requested *protocol.Address, logErr *log.Logger) {
	peer, ok := ctrl.RemoteAddr().(*net.TCPAddr)
	if !ok || requested.Domain != "" || (requested.IP != nil && !requested.IP.IsUnspecified() && !requested.IP.Equal(peer.IP)) {
		_, _ = ctrl.Write([]byte{socksVer, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	bindIP := net.IPv4(127, 0, 0, 1)
	if peer.IP.To4() == nil {
		bindIP = net.IPv6loopback
	}
	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		if logErr != nil {
			logErr.Printf("socks-udp: listen: %v", err)
		}
		_, _ = ctrl.Write([]byte{socksVer, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpSock.Close()

	relay, err := ud.OpenUDPRelay(ctx)
	if err != nil {
		if logErr != nil {
			logErr.Printf("socks-udp: relay open: %v", err)
		}
		return
	}
	defer relay.Close()
	var reply bytes.Buffer
	reply.Write([]byte{socksVer, 0, 0})
	bound := udpSock.LocalAddr().(*net.UDPAddr)
	if err := (&protocol.Address{Type: protocol.ATypIPv6, IP: bound.IP, Port: uint16(bound.Port)}).Encode(&reply); err != nil {
		return
	}
	// Use an IPv4 address tag when the association is IPv4.
	if bound.IP.To4() != nil {
		reply.Reset()
		reply.Write([]byte{socksVer, 0, 0})
		_ = (&protocol.Address{Type: protocol.ATypIPv4, IP: bound.IP, Port: uint16(bound.Port)}).Encode(&reply)
	}
	if _, err := ctrl.Write(reply.Bytes()); err != nil {
		return
	}
	var once sync.Once
	closeAll := func() { once.Do(func() { _ = udpSock.Close(); _ = relay.Close(); _ = ctrl.Close() }) }
	defer closeAll()
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()

	// Track the single app using this association (typical SOCKS5 usage).
	var lastClient *net.UDPAddr
	var mu sync.Mutex
	done := make(chan struct{}, 3)
	// RFC 1928: the association ends when its TCP control connection ends.
	go func() { defer func() { closeAll(); done <- struct{}{} }(); _, _ = io.Copy(io.Discard, ctrl) }()

	// App → tunnel.
	go func() {
		defer func() { closeAll(); done <- struct{}{} }()
		buf := make([]byte, 65535)
		for {
			n, from, err := udpSock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.Equal(peer.IP) || (requested.Port != 0 && from.Port != int(requested.Port)) {
				continue
			}
			dst, payload, err := parseSocksUDPHeader(buf[:n])
			if err != nil {
				continue // drop malformed (FRAG unsupported etc.)
			}
			mu.Lock()
			if lastClient == nil {
				lastClient = from
			}
			owner := lastClient.IP.Equal(from.IP) && lastClient.Port == from.Port
			mu.Unlock()
			if !owner {
				continue
			}
			if err := protocol.WriteUDPFrame(relay, dst, payload); err != nil {
				return
			}
		}
	}()

	// Tunnel → app.
	go func() {
		defer func() { closeAll(); done <- struct{}{} }()
		for {
			src, payload, err := protocol.ReadUDPFrame(relay)
			if err != nil {
				return
			}
			mu.Lock()
			dst := lastClient
			mu.Unlock()
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
	}()
	for range 3 {
		<-done
	}
}

// parseSocksUDPHeader strips [RSV u16][FRAG u8] then reads our Address.
func parseSocksUDPHeader(dgram []byte) (*protocol.Address, []byte, error) {
	if len(dgram) < 4 {
		return nil, nil, io.ErrShortBuffer
	}
	if dgram[0] != 0 || dgram[1] != 0 {
		return nil, nil, io.ErrUnexpectedEOF
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
