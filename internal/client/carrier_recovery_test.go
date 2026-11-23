package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"opentunnel/internal/transport"
)

func TestCarrierRecoveryRechecksExpiredQUICWithoutRetryingRejectedSSH(t *testing.T) {
	a := testAdaptiveLadder(t)
	a.SetHostile(true)
	a.mu.Lock()
	a.idx = a.sshTierIndex()
	a.lastProbe = time.Now()
	a.sshCooldown = time.Now().Add(sshRejectCooldown)
	a.tierCooldown = map[int]time.Time{len(profileOrder): time.Now().Add(-time.Second)}
	a.mu.Unlock()
	var attempts []string
	value, err := adaptiveAttempt(a, t.Context(), func(cl *Client) (string, error) {
		attempts = append(attempts, cl.Transport.Name())
		if cl.Transport.Name() != H3TierName {
			return "", errors.New("unexpected unavailable carrier")
		}
		return "verified synthetic QUIC", nil
	})
	if err != nil || value == "" || len(attempts) != 1 || attempts[0] != H3TierName {
		t.Fatal("expired faster carrier remained stranded by sticky rejected SSH", attempts, err)
	}
}

func TestCarrierRecoveryReservesOneStrictTLSProbeUnderBurst(t *testing.T) {
	a := testAdaptiveLadder(t)
	a.SetHostile(true)
	a.mu.Lock()
	a.tcpRetryAt = time.Now().Add(-time.Second)
	a.sshCooldown = time.Now().Add(sshRejectCooldown)
	a.tierCooldown = map[int]time.Time{len(profileOrder): time.Now().Add(time.Minute)}
	a.mu.Unlock()
	var attempts atomic.Int32
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() {
			_, _ = adaptiveAttempt(a, t.Context(), func(cl *Client) (bool, error) {
				attempts.Add(1)
				return false, errors.New("transport: server certificate fingerprint mismatch")
			})
		})
	}
	wg.Wait()
	if attempts.Load() != 1 {
		t.Fatal("browser burst bypassed strict-TLS recovery retry reservation", attempts.Load())
	}
	if a.ConnectionVerified() {
		t.Fatal("failed strict TLS recovery claimed verified connectivity")
	}
}

func TestCarrierUnavailableRetainsKeyRejectionCategoryAndRetry(t *testing.T) {
	a := testAdaptiveLadder(t)
	a.SetHostile(true)
	a.mu.Lock()
	a.sshCooldown = time.Now().Add(sshRejectCooldown)
	a.tierCooldown = map[int]time.Time{len(profileOrder): time.Now().Add(time.Minute)}
	a.lastFailure = "ssh-key-rejected"
	a.mu.Unlock()
	_, err := adaptiveAttempt(a, t.Context(), func(*Client) (bool, error) { t.Fatal("cooling carrier was retried"); return false, nil })
	var unavailable *CarrierUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Failure != "ssh-key-rejected" || !unavailable.RetryAt.After(time.Now()) {
		t.Fatal("cooldown erased the actionable previous failure", err)
	}
}

func TestCarrierRecoveryDoesNotEscalateOperatorOrCapacityDenial(t *testing.T) {
	for _, denial := range []error{&PendingError{Status: "pending"}, &BlockedError{Kind: "banned", Reason: "synthetic"}, ErrMuxCapacity} {
		a := testAdaptiveLadder(t)
		calls := 0
		_, err := adaptiveAttempt(a, context.Background(), func(*Client) (bool, error) { calls++; return false, denial })
		if err != denial || calls != 1 {
			t.Fatal("admission or local capacity denial retried across carriers", calls, err)
		}
	}
}

func TestSSHRejectionClassificationDoesNotPretendItIsTLSFailure(t *testing.T) {
	if category := runtimeFailureCategory(&transport.SSHKeyRejectedError{Host: "synthetic.invalid:22", Err: errors.New("synthetic rejection")}); category != "ssh-key-rejected" {
		t.Fatal("SSH approval failure hidden as generic connectivity", category)
	}
}
