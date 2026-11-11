package client

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

type namedTestTransport struct {
	name  string
	err   error
	calls atomic.Int32
}

func (t *namedTestTransport) Name() string { return t.name }
func (t *namedTestTransport) Dial(context.Context) (net.Conn, error) {
	t.calls.Add(1)
	return nil, t.err
}

func testAdaptiveLadder(t *testing.T) *Adaptive {
	t.Helper()
	a := NewAdaptive("test-adaptive-token", transport.WSTLSOptions{}, "auto", time.Second)
	a.UseTransportBuilder(func(profile string) transport.Transport { return &namedTestTransport{name: profile} })
	a.EnableH3(func() transport.Transport { return &namedTestTransport{name: H3TierName} })
	a.EnableSSHFallback(func() transport.Transport { return &namedTestTransport{name: SshTierName} })
	t.Cleanup(func() { _ = a.Close(); setHostileMode(false) })
	return a
}

func TestHostileStickySSHDoesNotRetryBlockedQUIC(t *testing.T) {
	a := testAdaptiveLadder(t)
	a.SetHostile(true)
	calls := map[string]int{}
	for i := 0; i < 5; i++ {
		name, err := adaptiveAttempt(a, context.Background(), func(cl *Client) (string, error) {
			name := cl.Transport.Name()
			calls[name]++
			if name != SshTierName {
				return "", errors.New("blocked carrier")
			}
			return name, nil
		})
		if err != nil || name != SshTierName {
			t.Fatal("working SSH carrier was not selected")
		}
	}
	if calls[H3TierName] != 1 || calls[SshTierName] != 5 || calls[ProfileStealth] != 0 {
		t.Fatalf("dead carriers were retried ahead of sticky SSH: %v", calls)
	}
}

func TestCarrierDeadlineDoesNotAbortFallback(t *testing.T) {
	a := testAdaptiveLadder(t)
	name, err := adaptiveAttempt(a, context.Background(), func(cl *Client) (string, error) {
		if cl.Transport.Name() != SshTierName {
			return "", context.DeadlineExceeded // this carrier's setup budget, not the caller
		}
		return SshTierName, nil
	})
	if err != nil || name != SshTierName {
		t.Fatalf("transport-owned timeout prevented failover: %v", err)
	}
}

func TestCallerCancellationDoesNotTryMoreTiers(t *testing.T) {
	a := testAdaptiveLadder(t)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := adaptiveAttempt(a, ctx, func(*Client) (string, error) {
		calls++
		cancel()
		return "", errors.New("failed")
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("caller cancellation did not stop the ladder")
	}
}

func TestHostileSSHOptOutAppliesWhenPinFailureLatchesMidDial(t *testing.T) {
	a := testAdaptiveLadder(t)
	a.AllowHostileSSH = false
	sshCalls := 0
	_, err := adaptiveAttempt(a, context.Background(), func(cl *Client) (string, error) {
		if cl.Transport.Name() == SshTierName {
			sshCalls++
			return SshTierName, nil
		}
		return "", errors.New("transport: server certificate fingerprint mismatch")
	})
	if err == nil || sshCalls != 0 {
		t.Fatal("mid-dial hostile latch bypassed the explicit SSH opt-out")
	}
}

func TestProfilesUseTheirActualShapingSettings(t *testing.T) {
	a := testAdaptiveLadder(t)
	for idx, profile := range profileOrder {
		if a.build(idx).opts.Profile != profile {
			t.Fatalf("%s tier did not use its own shaping profile", profile)
		}
	}
}

func TestSSHRejectionCooldownIsSharedByControlAndProbes(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	a := NewAdaptive("synthetic-token", transport.WSTLSOptions{}, "auto", time.Second)
	tr := &namedTestTransport{name: SshTierName, err: &transport.SSHKeyRejectedError{Host: "fixture:22", Err: errors.New("refused")}}
	a.EnableSSHFallback(func() transport.Transport { return tr })
	a.EnableMux()
	a.idx, a.lastProbe = len(profileOrder), time.Now()
	defer a.Close()
	_, _ = a.CtrlExchange(context.Background(), protocol.CtrlRequest{Op: "health"})
	_, _ = a.Probe(context.Background())
	_, _ = a.OpenUDPRelay(context.Background())
	if tr.calls.Load() != 2 {
		t.Fatalf("control/probe path bypassed SSH cooldown: %d attempts", tr.calls.Load())
	}
}

func TestFixedFastProfileDoesNotEscalate(t *testing.T) {
	a := testAdaptiveLadder(t)
	a.auto = false
	calls := 0
	_, _ = adaptiveAttempt(a, context.Background(), func(*Client) (string, error) {
		calls++
		return "", errors.New("failed")
	})
	if calls != 1 || a.idx != 0 {
		t.Fatal("fixed fast profile silently escalated")
	}
}
