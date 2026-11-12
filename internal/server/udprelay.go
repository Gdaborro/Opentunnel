package server

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"opentunnel/internal/protocol"
)

// serveUDPStream uses the same policy, aggregate pacing and accounting as
// TCP. The independent watcher stops downstream-only traffic after a policy
// change; replies are accepted only from recently contacted destinations.
func serveUDPStream(rw io.ReadWriteCloser, opt Options, token, peerStatus, ingress string) {
	defer rw.Close()
	opt.ensureState()
	if _, denied, _ := opt.freshDataPolicy(token, peerStatus); denied != "" {
		return
	}
	if d, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(time.Now().Add(opt.setupTimeout()))
	}
	var up, down atomic.Int64
	defer func() {
		if _, durable := opt.PanelDB.(trafficStore); !durable && opt.PanelDB != nil && token != "" {
			opt.PanelDB.RecordTraffic(token, up.Load(), down.Load())
		}
	}()
	var pc net.PacketConn
	var pcMu sync.Mutex
	var workerDone chan struct{}
	closeData := func() {
		_ = rw.Close()
		pcMu.Lock()
		if pc != nil {
			_ = pc.Close()
		}
		pcMu.Unlock()
	}
	defer func() {
		closeData()
		if workerDone != nil {
			<-workerDone
		}
	}()
	ctx, stopWatch := opt.watchData(token, peerStatus, closeData)
	defer stopWatch()
	var destinationsMu sync.Mutex
	destinations := make(map[string]time.Time)
	ensurePC := func() error {
		pcMu.Lock()
		defer pcMu.Unlock()
		if pc != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		pc, err = net.ListenPacket("udp", "")
		if err != nil {
			return err
		}
		workerDone = make(chan struct{})
		go func(conn net.PacketConn) {
			defer close(workerDone)
			buf := make([]byte, 65535)
			for {
				n, from, err := conn.ReadFrom(buf)
				if err != nil {
					return
				}
				destinationsMu.Lock()
				until, known := destinations[from.String()]
				destinationsMu.Unlock()
				if !known || time.Now().After(until) {
					continue
				}
				src := udpAddrToAddress(from)
				if src == nil {
					continue
				}
				written, err := opt.packetTraffic(ctx, token, peerStatus, ingress, true, n, func() (int, error) {
					if err := protocol.WriteUDPFrame(rw, src, buf[:n]); err != nil {
						return 0, err
					}
					return n, nil
				})
				down.Add(int64(written))
				if err != nil {
					closeData()
					return
				}
			}
		}(pc)
		return nil
	}
	first := true
	for {
		dst, payload, err := protocol.ReadUDPFrame(rw)
		if err != nil {
			return
		}
		if first {
			first = false
			if d, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
				_ = d.SetDeadline(time.Time{})
			}
		}
		if dst.Port == 0 {
			continue
		}
		name := dst.Domain
		if name == "" && dst.IP != nil {
			name = dst.IP.String()
		}
		if opt.PanelDB != nil && opt.PanelDB.IsBlocked(name) {
			continue
		}
		raddr, err := resolveUDP(ctx, dst)
		if err != nil {
			continue
		}
		if !opt.AllowRestrictedTargets && isRestrictedIP(raddr.IP) {
			continue
		}
		if err := ensurePC(); err != nil {
			return
		}
		destinationsMu.Lock()
		if len(destinations) >= 512 {
			for name, until := range destinations {
				if time.Now().After(until) {
					delete(destinations, name)
				}
			}
		}
		_, exists := destinations[raddr.String()]
		if !exists && len(destinations) >= 512 {
			destinationsMu.Unlock()
			continue
		}
		destinations[raddr.String()] = time.Now().Add(2 * time.Minute)
		destinationsMu.Unlock()
		written, err := opt.packetTraffic(ctx, token, peerStatus, ingress, false, len(payload), func() (int, error) { return pc.WriteTo(payload, raddr) })
		up.Add(int64(written))
		if err != nil {
			return
		}
	}
}

func resolveUDP(ctx context.Context, dst *protocol.Address) (*net.UDPAddr, error) {
	if dst.IP != nil {
		return &net.UDPAddr{IP: dst.IP, Port: int(dst.Port)}, nil
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(dctx, dst.Domain)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: dst.Domain}
	}
	return &net.UDPAddr{IP: addrs[0].IP, Zone: addrs[0].Zone, Port: int(dst.Port)}, nil
}

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
