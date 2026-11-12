package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"opentunnel/internal/access"
)

const (
	policyTTL        = time.Second
	maxActiveStreams = 2048
	maxDeviceStreams = 384
	trafficChunk     = 32 << 10
)

type cachedPolicy struct {
	p   access.Snapshot
	err error
	at  time.Time
}

type policyLoad struct {
	done chan struct{}
	p    access.Snapshot
	err  error
}

type sharedLimiter struct {
	lim  *rate.Limiter
	last time.Time
}

// relayState belongs to ONE handler / database, never to a process-global
// token cache. Limits cover all sessions, carriers and both traffic directions.
type relayState struct {
	mu            sync.Mutex
	policies      map[string]cachedPolicy
	loading       map[string]*policyLoad
	limits        map[string]*sharedLimiter
	deviceStreams map[string]int
	streams       chan struct{}
}

func newRelayState() *relayState {
	return &relayState{policies: make(map[string]cachedPolicy), limits: make(map[string]*sharedLimiter),
		loading: make(map[string]*policyLoad), deviceStreams: make(map[string]int), streams: make(chan struct{}, maxActiveStreams)}
}

func (o *Options) ensureState() {
	if o.state == nil {
		o.state = newRelayState()
	}
}

func (o Options) readPolicy(token string) (access.Snapshot, error) {
	if o.PanelDB == nil {
		return access.Snapshot{Status: "approved"}, nil
	}
	if store, ok := o.PanelDB.(interface {
		AccessPolicy(string) (access.Snapshot, error)
	}); ok {
		return store.AccessPolicy(token)
	}
	// Compatibility for embedders and synthetic tests. Errors still fail
	// closed; there is deliberately no session-snapshot approval fallback.
	status, reason, expires, err := o.PanelDB.CheckToken(token)
	if err != nil {
		return access.Snapshot{}, err
	}
	maxBps, quota := o.PanelDB.PeerLimits(token)
	sshMax, sshDaily, sshTrickle := o.PanelDB.SSHTierLimits()
	return access.Snapshot{Status: status, Reason: reason, Expires: expires,
		PublicKey: o.PanelDB.SSHPubKey(token), MaxBps: maxBps, QuotaBytes: quota,
		V5Seen:     o.PanelDB.V5Seen(token),
		KillSwitch: o.PanelDB.KillSwitch(), KillAllowed: o.PanelDB.KillSwitchAllow(token),
		KillReason: o.PanelDB.KillSwitchReason(), SSHMaxBps: sshMax,
		SSHDailyBytes: sshDaily, SSHTrickleBps: sshTrickle, SSHUsedBytes: sshBudgetUsed(token)}, nil
}

func (o Options) policy(token string) (access.Snapshot, error) {
	if o.state == nil || o.PanelDB == nil {
		return o.readPolicy(token)
	}
	o.state.mu.Lock()
	if e, ok := o.state.policies[token]; ok && time.Since(e.at) < policyTTL {
		o.state.mu.Unlock()
		return e.p, e.err
	}
	if load := o.state.loading[token]; load != nil {
		o.state.mu.Unlock()
		<-load.done
		return load.p, load.err
	}
	if len(o.state.loading) >= 1024 {
		o.state.mu.Unlock()
		return access.Snapshot{}, errors.New("policy lookup capacity reached")
	}
	load := &policyLoad{done: make(chan struct{})}
	o.state.loading[token] = load
	o.state.mu.Unlock()
	// A slow SQL read must not hold the shared stream/limiter mutex.
	p, err := o.readPolicy(token)
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	load.p, load.err = p, err
	delete(o.state.loading, token)
	close(load.done)
	if len(o.state.policies) >= 4096 {
		for token, e := range o.state.policies {
			if time.Since(e.at) >= policyTTL {
				delete(o.state.policies, token)
			}
		}
	}
	if len(o.state.policies) < 4096 {
		o.state.policies[token] = cachedPolicy{p: p, err: err, at: time.Now()}
	}
	return p, err
}

func (o Options) invalidatePolicy(token string) {
	if o.state != nil {
		o.state.mu.Lock()
		delete(o.state.policies, token)
		o.state.mu.Unlock()
	}
}

// dataPolicy permits only approved identities. The generation and key are
// bound to the handshake, preventing old warm sessions from reviving after a
// rekey, unban or expiry followed by approval.
func (o Options) dataPolicy(token, peerStatus string) (access.Snapshot, string, string) {
	p, err := o.policy(token)
	return o.checkDataPolicy(p, err, peerStatus)
}

// Stream admission is an authority read, not a cached hot-path write check.
// A freshly opened stream must not receive OK using a pre-toggle snapshot.
func (o Options) freshDataPolicy(token, peerStatus string) (access.Snapshot, string, string) {
	p, err := o.readPolicy(token)
	return o.checkDataPolicy(p, err, peerStatus)
}

func (o Options) checkDataPolicy(p access.Snapshot, err error, peerStatus string) (access.Snapshot, string, string) {
	if err != nil {
		return p, "unavailable", "admission unavailable"
	}
	if o.PanelDB == nil {
		p.Status = peerStatus
	}
	if p.KillSwitch && !p.KillAllowed {
		reason := p.KillReason
		if reason == "" {
			reason = "shut down till further notice"
		}
		return p, "down", reason
	}
	if o.sessionBound && (p.Generation != o.sessionGeneration || p.PublicKey != o.sessionPublicKey) {
		return p, "revoked", "session identity revoked"
	}
	if p.Status != "approved" {
		switch p.Status {
		case "pending", "expired", "banned", "kicked", "kicked-silent":
			return p, p.Status, p.Reason
		default:
			return p, "unavailable", "unknown admission state"
		}
	}
	return p, "", ""
}

func (o Options) acquireStream(token string) func() {
	if o.state == nil {
		return func() {}
	}
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	if o.state.deviceStreams[token] >= maxDeviceStreams {
		return nil
	}
	select {
	case o.state.streams <- struct{}{}:
	default:
		return nil
	}
	o.state.deviceStreams[token]++
	var once sync.Once
	return func() {
		once.Do(func() {
			o.state.mu.Lock()
			defer o.state.mu.Unlock()
			<-o.state.streams
			o.state.deviceStreams[token]--
			if o.state.deviceStreams[token] == 0 {
				delete(o.state.deviceStreams, token)
			}
		})
	}
}

// watchData checks policy even if the client sends nothing, including
// server-to-client-only UDP and TCP downloads. It closes endpoints to unblock
// copies and returns a stop function that joins the watcher at teardown.
func (o Options) watchData(token, status string, closeData func()) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(policyTTL)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, denied, _ := o.dataPolicy(token, status); denied != "" {
					cancel()
					closeData()
					return
				}
			}
		}
	}()
	return ctx, func() { cancel(); <-done }
}

func (o Options) limit(token, scope string, bps int64) *rate.Limiter {
	if bps <= 0 || o.state == nil {
		return nil
	}
	key := token + "|" + scope
	o.state.mu.Lock()
	defer o.state.mu.Unlock()
	if len(o.state.limits) >= 8192 {
		for key, e := range o.state.limits {
			if time.Since(e.last) > 5*time.Minute {
				delete(o.state.limits, key)
			}
		}
	}
	e := o.state.limits[key]
	if e == nil {
		e = &sharedLimiter{lim: rate.NewLimiter(rate.Limit(bps), trafficChunk)}
		o.state.limits[key] = e
	} else if e.lim.Limit() != rate.Limit(bps) {
		// Do not replenish a bucket on each stream or policy refresh.
		e.lim.SetLimit(rate.Limit(bps))
	}
	e.last = time.Now()
	return e.lim
}

func (o Options) pace(ctx context.Context, token, ingress string, p access.Snapshot, n int) error {
	if lim := o.limit(token, "device", p.MaxBps); lim != nil {
		for remaining := n; remaining > 0; {
			chunk := min(remaining, trafficChunk)
			if err := lim.WaitN(ctx, chunk); err != nil {
				return err
			}
			remaining -= chunk
		}
	}
	if ingress == IngressSSH {
		bps := p.SSHMaxBps
		if p.SSHDailyBytes > 0 && p.SSHUsedBytes >= p.SSHDailyBytes {
			trickle := p.SSHTrickleBps
			if trickle <= 0 {
				trickle = defaultPostBudgetBps
			}
			bps = lowerPositive(bps, trickle)
		}
		if lim := o.limit(token, IngressSSH, bps); lim != nil {
			for remaining := n; remaining > 0; {
				chunk := min(remaining, trafficChunk)
				if err := lim.WaitN(ctx, chunk); err != nil {
					return err
				}
				remaining -= chunk
			}
		}
	}
	return nil
}

func (o Options) packetTraffic(ctx context.Context, token, status, ingress string, down bool, n int, send func() (int, error)) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	p, denied, _ := o.dataPolicy(token, status)
	if denied != "" {
		return 0, errors.New("UDP traffic denied: " + denied)
	}
	if err := o.pace(ctx, token, ingress, p, n); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store, durable := o.PanelDB.(trafficStore)
	var reservation access.Reservation
	if durable && n > 0 {
		var err error
		reservation, err = store.ReserveTraffic(ctx, token, p.Generation, ingress, down, n)
		if err != nil {
			return 0, err
		}
		if reservation.Bytes != n {
			_ = store.RefundTraffic(context.WithoutCancel(ctx), token, p.Generation, ingress, down, reservation, reservation.Bytes)
			return 0, errors.New("insufficient quota for complete datagram")
		}
	}
	written, err := send()
	if written < 0 || written > n {
		written, err = 0, io.ErrShortWrite
	}
	if durable && n-written > 0 {
		if refundErr := store.RefundTraffic(context.WithoutCancel(ctx), token, p.Generation, ingress, down, reservation, n-written); refundErr != nil {
			return written, refundErr
		}
	} else if !durable && ingress == IngressSSH && p.SSHDailyBytes > 0 {
		sshBudgetAdd(token, int64(written))
	}
	return written, err
}

type trafficStore interface {
	ReserveTraffic(ctx context.Context, token, generation, ingress string, down bool, n int) (access.Reservation, error)
	RefundTraffic(ctx context.Context, token, generation, ingress string, down bool, reservation access.Reservation, n int) error
}

type trafficConn struct {
	io.ReadWriteCloser
	o                      Options
	ctx                    context.Context
	token, status, ingress string
	down                   bool
	bytes                  int64 // written by one copy worker; read only after that worker joins
}

func (w *trafficConn) CloseWrite() error {
	if cw, ok := w.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return w.Close()
}

func (w *trafficConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		if err := w.ctx.Err(); err != nil {
			return total, err
		}
		p, denied, _ := w.o.dataPolicy(w.token, w.status)
		if denied != "" {
			return total, errors.New("relay traffic denied: " + denied)
		}
		n := min(len(b), trafficChunk)
		if err := w.o.pace(w.ctx, w.token, w.ingress, p, n); err != nil {
			return total, err
		}
		if err := w.ctx.Err(); err != nil {
			return total, err
		}
		store, durable := w.o.PanelDB.(trafficStore)
		var reservation access.Reservation
		if durable {
			var err error
			reservation, err = store.ReserveTraffic(w.ctx, w.token, p.Generation, w.ingress, w.down, n)
			if err != nil {
				return total, err
			}
			n = reservation.Bytes
		}
		written, err := w.ReadWriteCloser.Write(b[:n])
		if written < 0 || written > n {
			written, err = 0, io.ErrShortWrite
		}
		total += written
		w.bytes += int64(written)
		if durable {
			if refundErr := store.RefundTraffic(context.WithoutCancel(w.ctx), w.token, p.Generation, w.ingress, w.down, reservation, n-written); refundErr != nil {
				return total, refundErr
			}
		} else if w.ingress == IngressSSH && p.SSHDailyBytes > 0 {
			sshBudgetAdd(w.token, int64(written))
		}
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
		b = b[n:]
	}
	return total, nil
}
