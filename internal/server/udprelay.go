package server

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"opentunnel/internal/protocol"
)

// serveUDPStream relays UDP datagrams between one mux stream and the
// internet. Each datagram frame carries its destination (upstream) or source
// (downstream) address, so no NAT table is needed:
//
//	client → server: [u16][ATYP addr port][payload]  (destination)
//	server → client: [u16][ATYP addr port][payload]  (source)
//
// Destinations pass the same SSRF filter and blocklist as TCP targets.
// Identity rules apply identically to the TCP relay (pentest 2026-10-25):
// banned/kicked devices get nothing, bytes are accounted per device, and
// per-device bandwidth caps pace datagram writes. ssh ingress adds the
// ssh-tier containment policy (sshtier.go): cap + daily budget.
func serveUDPStream(rw io.ReadWriteCloser, opt Options, token, peerStatus, ingress string) {
	defer rw.Close()

	switch peerStatus {
	case "banned", "kicked", "kicked-silent":
		// Identity enforcement used to stop at the TCP relay: UDP streams
		// kept flowing for banned/kicked devices with zero accounting.
		return
	}
	// Live verdict (1.0.1): a ban/kick that lands mid-session must stop
	// datagram flow too, not just the next handshake.
	if st, _, _, ok := opt.currentVerdict(token); ok && (st == "banned" || st == "kicked") {
		return
	}
	// Setup deadline: without it a peer could open UDP streams and never
	// send a frame, holding a stream slot and the session semaphore
	// forever (1.0.1). Lifted on the first datagram.
	if d, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(time.Now().Add(15 * time.Second))
	}

	// Per-device cap + ssh-tier containment: datagrams used to leave
	// unmeasured; the same policy that paces TCP streams now paces
	// datagram writes and counts against the device's ssh daily budget.
	pol := resolveStreamPolicy(opt, token, ingress)
	var lim *rate.Limiter
	if pol.limitBps > 0 {
		lim = rate.NewLimiter(rate.Limit(pol.limitBps), int(pol.limitBps))
	}

	var up, down atomic.Int64
	if opt.PanelDB != nil && token != "" {
		defer func() {
			opt.PanelDB.RecordTraffic(token, up.Load(), down.Load())
			if pol.budgetBytes > 0 {
				sshBudgetAdd(token, up.Load()+down.Load())
			}
		}()
	}

	// The outbound UDP socket is created lazily on the first datagram: a
	// stream that never sends one costs nothing (1.0.1 — every mux stream
	// used to mint a socket plus a 64 KiB read goroutine up front, so 512
	// idle streams per session exhausted relay fds).
	var pc net.PacketConn
	var pcOnce sync.Once
	var pcErr error
	defer func() {
		if pc != nil {
			_ = pc.Close()
		}
	}()
	ensurePC := func() error {
		pcOnce.Do(func() {
			pc, pcErr = net.ListenPacket("udp", "")
			if pcErr != nil {
				return
			}
			// Socket → client.
			go func(conn net.PacketConn) {
				buf := make([]byte, 65535)
				for {
					n, from, rerr := conn.ReadFrom(buf)
					if rerr != nil {
						return
					}
					down.Add(int64(n))
					src := udpAddrToAddress(from)
					if src == nil {
						continue
					}
					if werr := protocol.WriteUDPFrame(rw, src, buf[:n]); werr != nil {
						return
					}
				}
			}(pc)
		})
		return pcErr
	}

	lastVerdict := time.Now()
	firstFrame := true
	for {
		dst, payload, err := protocol.ReadUDPFrame(rw)
		if err != nil {
			return
		}
		if firstFrame {
			firstFrame = false
			if d, ok := rw.(interface{ SetDeadline(time.Time) error }); ok {
				_ = d.SetDeadline(time.Time{})
			}
		}
		// Periodic live-verdict re-check: a mid-session ban/kick stops
		// datagrams within ~10s, independent of client cooperation.
		if time.Since(lastVerdict) > 10*time.Second {
			lastVerdict = time.Now()
			if st, _, _, ok := opt.currentVerdict(token); ok && (st == "banned" || st == "kicked") {
				return
			}
		}
		if err := ensurePC(); err != nil {
			opt.logger().Printf("server: udp relay listen: %v", err)
			return
		}
		// Kill switch drops datagrams while suspended — the operator's
		// allowlisted devices keep their UDP relay.
		if opt.PanelDB != nil && opt.PanelDB.KillSwitch() && !opt.PanelDB.KillSwitchAllow(token) {
			continue
		}
		// Blocklist applies to domains and IP literals alike.
		if opt.PanelDB != nil {
			name := dst.Domain
			if name == "" && dst.IP != nil {
				name = dst.IP.String()
			}
			if name != "" && opt.PanelDB.IsBlocked(name) {
				continue
			}
		}
		raddr, err := net.ResolveUDPAddr("udp", dst.HostPort())
		if err != nil {
			continue
		}
		// Post-resolution check covers domain targets resolving inward.
		if !opt.AllowRestrictedTargets && isRestrictedIP(raddr.IP) {
			continue
		}
		if lim != nil {
			if werr := lim.WaitN(context.Background(), len(payload)); werr != nil {
				continue
			}
		}
		n, err := pc.WriteTo(payload, raddr)
		up.Add(int64(n))
		if err != nil {
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
