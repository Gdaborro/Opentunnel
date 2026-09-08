package proxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"opentunnel/internal/protocol"
)

type fakeDialer struct {
	udp bool
}

func (f *fakeDialer) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (f *fakeDialer) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	if !f.udp {
		return nil, errors.New("no udp")
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func TestBanGatePassThrough(t *testing.T) {
	g := &BanGate{}
	d := &BanDialer{Inner: &fakeDialer{udp: true}, Gate: g}
	c, err := d.DialTunnel(context.Background(), &protocol.Address{Domain: "example.com", Port: 80})
	if err != nil {
		t.Fatalf("gate off must forward: %v", err)
	}
	_ = c.Close()
	u, err := d.OpenUDPRelay(context.Background())
	if err != nil {
		t.Fatalf("gate off must forward UDP: %v", err)
	}
	_ = u.Close()
}

func TestBanGateBlocksWithReason(t *testing.T) {
	g := &BanGate{}
	g.Activate("torrenting all night")
	if !g.Active() || g.Reason() != "torrenting all night" {
		t.Fatal("gate state wrong after Activate")
	}
	d := &BanDialer{Inner: &fakeDialer{udp: true}, Gate: g}
	if _, err := d.DialTunnel(context.Background(), &protocol.Address{Domain: "example.com", Port: 443}); err == nil {
		t.Fatal("gated dial must fail")
	} else if !strings.Contains(err.Error(), "banned:") || !strings.Contains(err.Error(), "torrenting") {
		t.Fatalf("gated dial must carry banned: + reason, got %v", err)
	}
	if _, err := d.OpenUDPRelay(context.Background()); err == nil {
		t.Fatal("gated UDP must fail")
	}
	// The gated error must render the Banned page variant with the reason.
	page := serveBlockPageHTML(&protocol.Address{Domain: "example.com", Port: 80}, d.Gate.Err())
	if !strings.Contains(page, "Banned") || !strings.Contains(page, "torrenting all night") {
		t.Fatal("ban page must show Banned badge and reason")
	}
}

func TestBanDialerNoInner(t *testing.T) {
	g := &BanGate{}
	g.Activate("")
	d := &BanDialer{Gate: g} // startup grace mode: no tunnel at all
	if _, err := d.DialTunnel(context.Background(), &protocol.Address{Domain: "x.test", Port: 80}); err == nil {
		t.Fatal("must fail without inner dialer")
	}
}
