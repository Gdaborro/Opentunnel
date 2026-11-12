package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"opentunnel/internal/access"
	"opentunnel/internal/protocol"
)

type mutablePolicy struct {
	killSwitchStub
	mu  sync.RWMutex
	p   access.Snapshot
	err error
}

func (s *mutablePolicy) AccessPolicy(string) (access.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.p, s.err
}
func (s *mutablePolicy) set(p access.Snapshot, err error) {
	s.mu.Lock()
	s.p, s.err = p, err
	s.mu.Unlock()
}

func TestDataPolicyDeniesAllNonApprovedAndErrorStates(t *testing.T) {
	s := &mutablePolicy{}
	o := Options{PanelDB: s, state: newRelayState()}
	for _, state := range []string{"pending", "expired", "banned", "kicked", "unknown", ""} {
		s.set(access.Snapshot{Status: state}, nil)
		o.invalidatePolicy("fixture")
		if _, denied, _ := o.dataPolicy("fixture", "approved"); denied == "" {
			t.Fatalf("state %q passed", state)
		}
	}
	s.set(access.Snapshot{Status: "approved"}, errors.New("SQL unavailable"))
	o.invalidatePolicy("fixture")
	if _, denied, _ := o.dataPolicy("fixture", "approved"); denied != "unavailable" {
		t.Fatalf("failure verdict=%q", denied)
	}
}

func TestWarmSessionCannotReviveAfterRekeyAndApproval(t *testing.T) {
	s := &mutablePolicy{p: access.Snapshot{Status: "approved", PublicKey: "old-key", Generation: "original"}}
	o := Options{PanelDB: s, state: newRelayState(), sessionBound: true, sessionPublicKey: "old-key", sessionGeneration: "original"}
	if _, denied, _ := o.dataPolicy("fixture", "approved"); denied != "" {
		t.Fatal(denied)
	}
	s.set(access.Snapshot{Status: "approved", PublicKey: "old-key", Generation: "replacement"}, nil)
	o.invalidatePolicy("fixture")
	if _, denied, _ := o.dataPolicy("fixture", "approved"); denied != "revoked" {
		t.Fatalf("old session revived: %q", denied)
	}
}

func TestRateBucketIsSharedAcrossStreamsAndDirections(t *testing.T) {
	o := Options{state: newRelayState()}
	p := access.Snapshot{MaxBps: 64 << 10}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := o.pace(ctx, "fixture", "", p, 32<<10); err != nil {
		t.Fatal(err)
	}
	if err := o.pace(ctx, "fixture", IngressSSH, p, 32<<10); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("new stream/carrier reset the device bucket")
	}
	if o.limit("fixture", "device", p.MaxBps) != o.limit("fixture", "device", p.MaxBps) {
		t.Fatal("limiter was allocated per stream")
	}
}

func TestStreamCapsAreAggregateAndReleaseIdempotently(t *testing.T) {
	o := Options{state: newRelayState()}
	var release []func()
	for range maxDeviceStreams {
		r := o.acquireStream("fixture")
		if r == nil {
			t.Fatal("early cap")
		}
		release = append(release, r)
	}
	if r := o.acquireStream("fixture"); r != nil {
		r()
		t.Fatal("device cap bypassed")
	}
	release[0]()
	release[0]()
	if r := o.acquireStream("fixture"); r == nil {
		t.Fatal("slot not released")
	} else {
		r()
	}
	for _, r := range release {
		r()
	}
}

func TestFirstMuxModeByteHasDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	o := Options{SetupTimeout: 100 * time.Millisecond, state: newRelayState()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		o.serveMuxSession(b, "fixture", "approved", "", protocol.ProtoVersionLegacy, "")
	}()
	sess, err := smux.Client(a, protocol.MuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle first-mode stream stayed open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("client backstop timed out; server did not close the idle stream")
	}
	_ = sess.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("mux handler did not terminate")
	}
}

func TestLiveIdleTCPStopsOnPolicyChange(t *testing.T) {
	for _, verdict := range []string{"pending", "expired", "banned", "kicked", "kill", "error"} {
		t.Run(verdict, func(t *testing.T) {
			s := &mutablePolicy{p: access.Snapshot{Status: "approved"}}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = c.Write([]byte("ready"))
				_, _ = io.Copy(io.Discard, c)
			}()
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				relayTarget(protocol.ATypIPv4, b, Options{PanelDB: s, AllowRestrictedTargets: true}, "fixture", "approved", "", protocol.ProtoVersionLegacy, "")
			}()
			target := protocol.AddrFromTCP(ln.Addr().(*net.TCPAddr))
			var frame bytes.Buffer
			_ = target.Encode(&frame)
			go func() { _, _ = a.Write(frame.Bytes()[1:]) }()
			_ = a.SetDeadline(time.Now().Add(4 * time.Second))
			if _, err := io.ReadFull(a, make([]byte, 2+len("ready"))); err != nil {
				t.Fatal(err)
			}
			p := access.Snapshot{Status: verdict}
			var fault error
			if verdict == "kill" {
				p.Status, p.KillSwitch = "approved", true
			}
			if verdict == "error" {
				p.Status = "approved"
				fault = errors.New("SQL unavailable")
			}
			s.set(p, fault)
			if _, err := a.Read(make([]byte, 1)); err == nil {
				t.Fatal("live TCP still flowed")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay copy workers did not join")
			}
		})
	}
}

func TestDownstreamOnlyUDPStopsOnKillSwitch(t *testing.T) {
	s := &mutablePolicy{p: access.Snapshot{Status: "approved"}}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveUDPStream(b, Options{PanelDB: s, AllowRestrictedTargets: true}, "fixture", "approved", "")
	}()
	target := udpAddrToAddress(pc.LocalAddr())
	if err := protocol.WriteUDPFrame(a, target, []byte("request")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	_, from, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = pc.WriteToUDP([]byte("response"), from) }()
	_ = a.SetDeadline(time.Now().Add(4 * time.Second))
	if _, payload, err := protocol.ReadUDPFrame(a); err != nil || string(payload) != "response" {
		t.Fatalf("reply=%q %v", payload, err)
	}
	s.set(access.Snapshot{Status: "approved", KillSwitch: true}, nil)
	// No further client datagrams: the independent watcher must still act.
	if _, _, err := protocol.ReadUDPFrame(a); err == nil {
		t.Fatal("UDP association survived kill")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP workers did not join")
	}
}
