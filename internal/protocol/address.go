// Package protocol defines the opentunnel wire protocol: target-address
// encoding, handshake, and request/response framing.
//
// M1 layout (all integers big-endian):
//
//	HandshakeRequest: magic[4]="OTU1" | version u8 | tokenLen u16 | token[tokenLen]
//	AuthResponse:     version u8 | status u8
//	TargetRequest:    Address
//	TargetResponse:   status u8
//	After TargetResponse(status==OK) the connection becomes a raw byte stream.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	// ProtoVersion 2: adds per-session salt + inner AEAD framing (crypt.go).
	// ProtoVersion 3: multiplexed sessions + UDP relay over dedicated streams;
	// after the secure stream is established the client sends exactly one
	// mode byte before anything else:
	//   MuxMarker  -> this connection carries smux streams
	//   UdpMarker  -> this stream relays UDP datagrams
	//   otherwise  -> the byte IS an ATYP: legacy single-target request
	ProtoVersion = 3

	StatusOK          = 0
	StatusBadToken    = 1
	StatusBadVersion  = 2
	StatusDialFailed  = 3
	StatusRateLimited = 4

	MuxMarker byte = 0x4D // 'M'
	UdpMarker byte = 0x55 // 'U'
)

// ModeName classifies a post-handshake mode byte for logging/errors.
func ModeName(b byte) string {
	switch b {
	case MuxMarker:
		return "mux"
	case UdpMarker:
		return "udp"
	case ATypIPv4, ATypDomain, ATypIPv6:
		return "single"
	default:
		return "unknown"
	}
}

var Magic = [4]byte{'O', 'T', 'U', '1'}

// Address is a target endpoint encoded SOCKS5-style.
type Address struct {
	Type   byte // 1=IPv4 3=Domain 4=IPv6
	Domain string
	IP     net.IP
	Port   uint16
}

const (
	ATypIPv4   byte = 1
	ATypDomain byte = 3
	ATypIPv6   byte = 4
)

func AddrFromTCP(addr *net.TCPAddr) *Address {
	if addr == nil {
		return &Address{Type: ATypIPv4, IP: net.IPv4zero}
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		return &Address{Type: ATypIPv4, IP: ip4, Port: uint16(addr.Port)}
	}
	return &Address{Type: ATypIPv6, IP: addr.IP, Port: uint16(addr.Port)}
}

func ParseAddress(host string, port int) (*Address, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return &Address{Type: ATypIPv4, IP: ip4, Port: uint16(port)}, nil
		}
		return &Address{Type: ATypIPv6, IP: ip, Port: uint16(port)}, nil
	}
	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("invalid hostname %q", host)
	}
	return &Address{Type: ATypDomain, Domain: host, Port: uint16(port)}, nil
}

// Encode writes the wire form of the address.
func (a *Address) Encode(w io.Writer) error {
	var buf []byte
	switch a.Type {
	case ATypIPv4:
		ip := a.IP.To4()
		if ip == nil {
			return errors.New("protocol: invalid IPv4 address")
		}
		buf = make([]byte, 0, 1+4+2)
		buf = append(buf, ATypIPv4)
		buf = append(buf, ip...)
	case ATypIPv6:
		buf = make([]byte, 0, 1+16+2)
		buf = append(buf, ATypIPv6)
		buf = append(buf, a.IP.To16()...)
	case ATypDomain:
		if len(a.Domain) == 0 || len(a.Domain) > 255 {
			return errors.New("protocol: invalid domain length")
		}
		buf = make([]byte, 0, 1+1+len(a.Domain)+2)
		buf = append(buf, ATypDomain, byte(len(a.Domain)))
		buf = append(buf, a.Domain...)
	default:
		return fmt.Errorf("protocol: unknown address type %d", a.Type)
	}
	port := [2]byte{}
	binary.BigEndian.PutUint16(port[:], a.Port)
	buf = append(buf, port[:]...)
	_, err := w.Write(buf)
	return err
}

func ReadAddress(r io.Reader) (*Address, error) {
	hdr := make([]byte, 1)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	return ReadAddressWithATYP(hdr[0], r)
}

// ReadAddressWithATYP parses an address whose type byte was already consumed
// (used when the first payload byte doubles as a mode/ATYP discriminator).
func ReadAddressWithATYP(atyp byte, r io.Reader) (*Address, error) {
	a := &Address{Type: atyp}
	switch atyp {
	case ATypIPv4:
		raw := make([]byte, 4+2)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, err
		}
		a.IP = net.IP(raw[:4])
		a.Port = binary.BigEndian.Uint16(raw[4:])
	case ATypIPv6:
		raw := make([]byte, 16+2)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, err
		}
		a.IP = net.IP(raw[:16])
		a.Port = binary.BigEndian.Uint16(raw[16:])
	case ATypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return nil, err
		}
		raw := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, err
		}
		a.Domain = string(raw[:l[0]])
		a.Port = binary.BigEndian.Uint16(raw[l[0]:])
	default:
		return nil, fmt.Errorf("protocol: unknown address type %d", atyp)
	}
	return a, nil
}

func (a *Address) HostPort() string {
	host := a.Domain
	if host == "" && a.IP != nil {
		host = a.IP.String()
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", a.Port))
}

func (a *Address) String() string { return a.HostPort() }
