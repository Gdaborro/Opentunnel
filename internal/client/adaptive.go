package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"opentunnel/internal/protocol"
	"opentunnel/internal/transport"
)

// Profile names, in escalation order: each step adds obfuscation overhead
// only when the previous one appears blocked or throttled. All profiles use
// a Chrome-fingerprint hello (stock Go handshakes are machine-identifiable);
// they differ in shaping, not identity.
const (
	ProfileFast     = "fast"     // Chrome hello, no shaping â€” fastest
	ProfileBalanced = "balanced" // + size-bucket padding
	ProfileStealth  = "stealth"  // + per-frame write jitter
)

var profileOrder = []string{ProfileFast, ProfileBalanced, ProfileStealth}

// SshTierName is the virtual last-resort tier riding inside real SSH.
const SshTierName = "ssh"

// sshRejectCooldown is how long the ssh tier pauses after sshd refuses
// the device's key twice in a row. A dead key is a configuration state:
// re-presenting it per request neither heals it nor looks like ordinary
// admin SSH — it looks like a credential-stuffing loop. Reset() (fired
// on panel approval) clears the cooldown immediately.
const sshRejectCooldown = 15 * time.Minute

const maxRetiredTierClients = 24

// H3TierName is the HTTP/3 tier: QUIC to :443 survives TLS interception
// (middleboxes cannot re-sign what they cannot terminate), sits between
// the ws-tls profiles and the ssh last resort, and carries bulk traffic
// on hostile networks so SSH doesn't have to.
const H3TierName = "h3"
const CarrierTierName = "carrier"

// tierCount returns how many tiers exist including the optional h3 and
// ssh fallbacks. In hostile mode the SSH tier is hidden unless explicitly
// allowed: an all-day SSH session is the most conspicuous state on an
// intercepting net. The h3 tier stays: it reads as ordinary HTTP/3.
func (a *Adaptive) tierCount() int {
	n := len(profileOrder)
	if a.carrierFallback != nil {
		n++
	}
	if a.h3Fallback != nil {
		n++
	}
	if a.sshFallback != nil && (!a.hostile || a.AllowHostileSSH) {
		n++
	}
	return n
}

// tierName maps a tier index to a display/build name.
func (a *Adaptive) tierName(idx int) string {
	if idx < len(profileOrder) {
		return profileOrder[idx]
	}
	n := len(profileOrder)
	if a.carrierFallback != nil {
		if idx == n {
			return CarrierTierName
		}
		n++
	}
	if a.h3Fallback != nil && idx == n {
		return H3TierName
	}
	return SshTierName
}

// sshTierIndex returns the ladder index of the ssh fallback tier, or -1
// when it is absent or hidden (hostile network without AllowHostileSSH).
// Must match tierCount's own gating exactly.
func (a *Adaptive) sshTierIndex() int {
	if a.sshFallback == nil || (a.hostile && !a.AllowHostileSSH) {
		return -1
	}
	n := len(profileOrder)
	if a.carrierFallback != nil {
		n++
	}
	if a.h3Fallback != nil {
		n++
	}
	return n
}

// ParseProfile validates a configured profile name ("auto" handled by NewAdaptive).
func ValidProfile(name string) bool {
	switch name {
	case "auto", ProfileFast, ProfileBalanced, ProfileStealth:
		return true
	}
	return false
}

// Adaptive picks profiles automatically. It starts at Fast, escalates when a
// profile fails or responds slower than TTFBBudget, and periodically re-probes
// lower profiles so users drop back to maximum speed whenever possible.
type Adaptive struct {
	poolSelector  *PoolSelector
	identityScope string
	mu            sync.Mutex
	token         string
	base          transport.WSTLSOptions
	idx           int // index into profileOrder
	auto          bool
	lastProbe     time.Time
	ttfbBudget    time.Duration
	dialTimeout   time.Duration
	factory       func(a *Adaptive, idx int) *Client
	Logger        *log.Logger // optional; nil = log.Default()
	mux           bool        // multiplexing requested by config
	failStreak    int         // consecutive failures on current tier
	lastFailure   string      // redacted runtime status category, never a destination/credential
	lastAdmission string
	generation    uint64 // network/config epoch; stale dials cannot relatch state
	verifiedAt    time.Time

	// clients caches one Client per tier so every browser connection reuses
	// the tier's warm mux pool instead of paying a full transport handshake
	// (TCP + TLS/SSH + auth) per request. Without this, page-load bursts
	// mint hundreds of handshakes and melt a small relay.
	clients        map[int]*Client
	retiredClients []*Client // preserve shutdown ownership of gracefully draining pools

	// transportBuilder lets configs swap the underlying transport per
	// profile (e.g. ssh). Defaults to ws-tls with Chrome hello above fast.
	transportBuilder func(profile string) transport.Transport

	// sshFallback, when set, adds a final last-resort tier that tunnels
	// inside real SSH — used when every ws-tls tier is intercepted.
	sshFallback func() transport.Transport

	// h3Fallback, when set, adds the HTTP/3 tier between the ws-tls
	// profiles and ssh: QUIC cannot be transparently intercepted, so the
	// pinned handshake reaches the relay untouched on MITM networks.
	h3Fallback         func() transport.Transport
	carrierFallback    func() transport.Transport
	innerTLSPins       []string
	requireChannelAuth bool

	// AllowHostileSSH permits the SSH tier while hostile mode is active
	// (TLS-intercepting network). Default true preserves connectivity;
	// set false to forbid the conspicuous SSH fallback on hostile nets.
	AllowHostileSSH bool

	// sshCooldown/sshRejects implement the ssh-tier backoff after sshd
	// refuses the device key (see noteSSHReject).
	sshCooldown  time.Time
	sshRejects   int
	tierCooldown map[int]time.Time // transient carrier failures, shared by data/control/probes
	tcpRetryAt   time.Time         // one bounded strict-TLS recovery probe, never a pin bypass
	tierFailures map[string]string
	closed       bool

	// hostile latches when every ws tier fails certificate pinning (TLS
	// interception): stealth shaping is locked on and beacons stretch.
	// Cleared on the first clean ws-tls dial (network changed).
	hostile bool

	// entries are the rotatable tunnel endpoints (primary first). rotateEntry
	// RotateEntry walks them when an entry fails outright (DNS death) or looks shaped;
	// the dial machinery always builds from the current entry.
	entries  []transport.WSTLSOptions
	entryIdx int

	// ProbeURL and ProbeSampleBytes override the throughput probe target
	// (empty/zero = defaults). Exported so tests and operators can aim the
	// probe at their own infrastructure.
	ProbeURL         string
	ProbeSampleBytes int64
	probeTLSConfig   *tls.Config // local test roots; production uses normal TLS verification

	// OnAuthRejected is forwarded to every built client: it fires when the
	// panel no longer knows the device token (purged/expired) so the device
	// can re-register and re-enter the approval queue.
	OnAuthRejected func()
}

// EnableMux turns on connection multiplexing for every profile's clients.
func (a *Adaptive) EnableMux() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mux = true
	a.invalidateClientsLocked()
}

// EnableSSHFallback adds the ssh last-resort tier to the ladder.
func (a *Adaptive) EnableSSHFallback(builder func() transport.Transport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sshFallback = builder
	a.invalidateClientsLocked()
}

// EnableCarrier adds an opt-in managed carrier before QUIC/SSH. It does not
// install, launch or configure a companion, or implicitly trust its credentials.
func (a *Adaptive) EnableCarrier(builder func() transport.Transport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.carrierFallback = builder
	a.invalidateClientsLocked()
}

func (a *Adaptive) EnableInnerTLS(pins []string) error {
	for _, value := range pins {
		if _, err := protocol.ParsePublicKeyPin(value); err != nil {
			return err
		}
	}
	if len(pins) == 0 {
		return errors.New("inner TLS requires a relay identity pin")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.innerTLSPins = append([]string(nil), pins...)
	a.invalidateClientsLocked()
	return nil
}

// EnableH3 adds the HTTP/3 tier to the ladder (between ws-tls and ssh).
func (a *Adaptive) EnableH3(builder func() transport.Transport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.h3Fallback = builder
	a.invalidateClientsLocked()
}

func (a *Adaptive) RequireChannelAuthentication() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.poolSelector != nil {
		if !a.poolSelector.profile.RequireChannelAuth {
			return errors.New("connection-bound pool requirement must come from the accepted signed profile")
		}
		a.requireChannelAuth = true
		return nil // each selected node's already-validated inner pins are applied by the selector
	}
	if len(a.innerTLSPins) == 0 {
		return errors.New("connection-bound authentication requires independent inner TLS pins")
	}
	a.requireChannelAuth = true
	a.invalidateClientsLocked()
	return nil
}

// EnableH3ForCurrentEntry keeps QUIC aligned with entry rotation and pins
// learned in-band. A closure over the startup config kept obsolete pins and
// the old entry forever, even after the WS tiers had learned a renewal.
func (a *Adaptive) EnableH3ForCurrentEntry() {
	a.EnableH3(func() transport.Transport {
		// defaultFactory invokes this while holding a.mu.
		return transport.NewH3(transport.H3Options{
			ServerAddr:    a.base.ServerAddr,
			ServerName:    a.base.ServerName,
			HTTPAuthority: a.base.HTTPAuthority,
			Path:          a.base.WSPath,
			Fingerprint:   a.base.Fingerprint,
			Fingerprints:  append([]string(nil), a.base.Fingerprints...),
			Insecure:      a.base.Insecure,
			DialTimeout:   a.dialTimeout,
		})
	})
}

// UseTransportBuilder overrides how per-profile transports are constructed.
func (a *Adaptive) UseTransportBuilder(f func(profile string) transport.Transport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.transportBuilder = f
	a.invalidateClientsLocked()
}

func (a *Adaptive) logger() *log.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return log.Default()
}

func NewAdaptive(token string, base transport.WSTLSOptions, profile string, dialTimeout time.Duration) *Adaptive {
	a := &Adaptive{
		token:           token,
		base:            base,
		auto:            profile == "auto",
		ttfbBudget:      3 * time.Second,
		dialTimeout:     dialTimeout,
		AllowHostileSSH: true,
	}
	a.factory = defaultFactory
	if !a.auto {
		for i, p := range profileOrder {
			if p == profile {
				a.idx = i
				break
			}
		}
	}
	return a
}

// h3MuxByteCap stops assigning NEW streams before an edge's request cap.
// This is not a hard request-body cap: an already active transfer may exceed
// it while draining and an HTTP front may then reset it. Real large-transfer
// acceptance must use the front's documented streaming limits, not this hint.
const h3MuxByteCap = 64 << 20

func defaultFactory(a *Adaptive, idx int) *Client {
	name := a.tierName(idx)
	var tr transport.Transport
	switch {
	case idx < len(profileOrder):
		if a.transportBuilder != nil {
			tr = a.transportBuilder(name)
		} else {
			opt := a.base
			opt.ChromeHello = true // every tier mimics Chrome (see const block)
			tr = transport.NewWSTLS(opt)
		}
	case name == CarrierTierName && a.carrierFallback != nil:
		tr = a.carrierFallback()
	case name == H3TierName && a.h3Fallback != nil:
		tr = a.h3Fallback()
	case a.sshFallback != nil:
		tr = a.sshFallback()
	default:
		opt := a.base
		opt.ChromeHello = true
		tr = transport.NewWSTLS(opt)
	}
	opts := Options{
		RequireChannelAuth: a.requireChannelAuth,
		IdentityScope:      a.identityScope,
		Token:              a.token,
		DialTimeout:        a.dialTimeout,
		Profile:            "balanced", // under h3/ssh, mild padding; harmless elsewhere
		Mux:                a.mux,
		OnAuthRejected:     a.OnAuthRejected,
	}
	if len(a.innerTLSPins) > 0 {
		wrapped, err := withScopedInnerTLS(tr, a.innerTLSPins, a.identityScope)
		if err != nil {
			panic("validated inner TLS pin configuration changed")
		}
		tr = wrapped
	}
	if idx < len(profileOrder) {
		opts.Profile = name // fast/balanced/stealth must actually shape differently
	}
	if name == H3TierName {
		opts.MuxByteCap = h3MuxByteCap
	}
	if tr.Name() == SshTierName {
		opts.MuxSessions = 2 // two warm + two draining fit the relay's loopback cap
	}
	return NewWithOptions(tr, opts)
}

func (a *Adaptive) SetIdentityScope(scope string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.identityScope = scope
	a.invalidateClientsLocked()
}

// UseTrustedPool installs one immutable operator selection and removes every
// unscoped fallback. Profile expiry is checked before new requests even when
// an existing warm mux session would otherwise bypass a transport dial.
func (a *Adaptive) UseTrustedPool(selector *PoolSelector) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.poolSelector, a.identityScope, a.token = selector, selector.profile.ID, ""
	a.requireChannelAuth = selector.profile.RequireChannelAuth
	a.transportBuilder = func(string) transport.Transport { return selector.Transport(a.dialTimeout) }
	a.sshFallback, a.h3Fallback, a.carrierFallback, a.innerTLSPins, a.entries = nil, nil, nil, nil, nil
	a.AllowHostileSSH = false
	a.invalidateClientsLocked()
}

func (a *Adaptive) build(idx int) *Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return &Client{setupError: net.ErrClosed}
	}
	a.pruneRetiredLocked()
	if a.clients == nil {
		a.clients = make(map[int]*Client)
	}
	if cl, ok := a.clients[idx]; ok {
		return cl
	}
	// Repeated pin/network changes cannot grow an unlimited set of active
	// draining clients. Backpressure new setup rather than kill old transfers.
	if len(a.retiredClients)+len(a.clients) >= maxRetiredTierClients {
		return &Client{setupError: ErrMuxCapacity}
	}
	cl := a.factory(a, idx)
	a.clients[idx] = cl
	return cl
}

// fatalUpstream reports errors that indicate the tunnel works but the target
// is unreachable â€” escalating profiles cannot help. Pending/expired device
// tokens and ISP blocks are also terminal: no transport tier can fix them.
func fatalUpstream(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrMuxCapacity) {
		return true // saturation must not create more pools on other carriers
	}
	// Caller cancellation is checked by adaptiveAttempt. A transport's own
	// shorter setup deadline must not prevent trying a different carrier.
	var pend *PendingError
	if errors.As(err, &pend) {
		return true
	}
	var be *BlockedError
	if errors.As(err, &be) {
		return true
	}
	var pe *protocol.StatusError
	return errors.As(err, &pe) && pe.Status == protocol.StatusDialFailed
}

// DialTunnel implements proxy.Dialer with adaptive tier selection.
func (a *Adaptive) DialTunnel(ctx context.Context, target *protocol.Address) (net.Conn, error) {
	return adaptiveAttempt(a, ctx, func(cl *Client) (net.Conn, error) {
		return cl.DialTunnel(ctx, target)
	})
}

// All users of the carrier ladder share selection and cooldowns. Previously
// the control/probe paths bypassed both and could keep trying rejected keys
// while the data path claimed the SSH tier was paused.
func adaptiveAttempt[T any](a *Adaptive, ctx context.Context, call func(*Client) (T, error)) (T, error) {
	var zero T
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return zero, net.ErrClosed
	}
	if a.poolSelector != nil {
		if err := a.poolSelector.profile.Verify(time.Now()); err != nil {
			a.mu.Unlock()
			return zero, err
		}
	}
	generation := a.generation
	start := a.idx
	probeDown := a.auto && start > 0 && time.Since(a.lastProbe) > 10*time.Minute
	// Probe downward early if the current tier keeps failing (e.g. the
	// fallback tier itself became unreachable) instead of waiting out the
	// full cool-off.
	if a.failStreak >= 3 {
		a.lastProbe = time.Now()
		a.failStreak = 0
		probeDown = start > 0
	}
	if probeDown {
		a.lastProbe = time.Now()
	}
	total := a.tierCount()
	hostile := a.hostile
	auto := a.auto
	if start >= total || start < 0 {
		start = 0
	}
	a.mu.Unlock()

	var order []int
	if probeDown {
		order = append(order, 0)
		for idx := len(profileOrder); idx < start; idx++ {
			order = append(order, idx) // occasionally recheck a faster carrier too
		}
	}
	// Honor the sticky working carrier. In particular, when SSH is working,
	// do NOT put blocked QUIC in front of it again on every browser request.
	if hostile && auto && start < len(profileOrder) && total > len(profileOrder) {
		start = len(profileOrder)
	}
	if !auto {
		order = []int{start} // fixed profile means exactly one tier
	} else {
		for i := start; i < total; i++ {
			if probeDown && i == 0 {
				continue
			}
			order = append(order, i)
		}
		// A sticky carrier is tried first. Only if it fails (or is cooling)
		// do we reconsider earlier optional carriers. An expired QUIC cooldown
		// must not stay unreachable merely because SSH was selected earlier.
		for idx := len(profileOrder); idx < start; idx++ {
			order = append(order, idx)
		}
		if hostile && !probeDown {
			order = append(order, 0) // the strict-TLS retry gate below bounds this
		}
	}

	var lastErr error
	sawPin := false
	sawDNS := false
	seen := map[int]bool{}
	for _, idx := range order {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if seen[idx] {
			continue
		}
		seen[idx] = true
		if (sawPin || sawDNS) && idx < len(profileOrder) {
			continue // changing padding cannot fix the identical failed pin
		}
		a.mu.Lock()
		if a.closed || a.generation != generation {
			a.mu.Unlock()
			return zero, ErrNetworkChanged
		}
		allowed := idx < a.tierCount() // hostile latching may hide the SSH tier mid-call
		sshIdx := a.sshTierIndex()
		cooling := time.Now().Before(a.tierCooldown[idx]) || (idx == sshIdx && time.Now().Before(a.sshCooldown))
		if idx < len(profileOrder) && a.hostile {
			if time.Now().Before(a.tcpRetryAt) {
				cooling = true
			} else if allowed && !cooling {
				// Reserve before releasing the mutex: a browser burst cannot
				// schedule a separate failed pin probe for every destination.
				a.tcpRetryAt = time.Now().Add(time.Minute)
			}
		}
		a.mu.Unlock()
		if cooling || !allowed {
			continue
		}
		cl := a.build(idx)
		t0 := time.Now()
		value, err := call(cl)
		a.mu.Lock()
		if a.closed || a.generation != generation {
			a.mu.Unlock()
			if err == nil {
				if closer, ok := any(value).(io.Closer); ok {
					_ = closer.Close()
				}
			}
			return zero, ErrNetworkChanged
		}
		if err == nil {
			a.lastFailure = ""
			a.verifiedAt = time.Now()
			failureName := a.tierName(idx)
			if idx < len(profileOrder) {
				failureName = "ws-tls"
			}
			delete(a.tierFailures, failureName)
			elapsed := time.Since(t0)
			clearedHostile := false
			a.failStreak = 0
			delete(a.tierCooldown, idx)
			if idx == sshIdx {
				a.sshRejects = 0
				a.sshCooldown = time.Time{}
			}
			if a.hostile && idx < len(profileOrder) && cl.Transport.Name() == "ws-tls" {
				a.hostile = false // clean ws-tls dial: network changed
				a.tcpRetryAt = time.Time{}
				setHostileMode(false)
				clearedHostile = true
			}
			switch {
			case probeDown && idx == 0:
				a.idx = 0 // lower profile healthy again â€” stay fast
				a.logger().Printf("adaptive: fast profile healthy again â€” back to %q", ProfileFast)
			default:
				if a.auto && idx != a.idx {
					a.idx = idx // escalated this call: stick here
					a.logger().Printf("adaptive: escalated to %q", a.tierName(idx))
					// Re-probe lower tiers only after a cool-off.
					a.lastProbe = time.Now()
				}
				// Slow-but-successful hints at active throttling of the
				// current tier: pre-escalate for subsequent dials.
				if a.auto && idx == a.idx && elapsed > a.ttfbBudget && a.idx+1 < total {
					a.idx++
					a.lastProbe = time.Now()
					a.logger().Printf("adaptive: slow response (%s) â€” pre-escalating to %q", elapsed.Round(time.Millisecond), a.tierName(a.idx))
				}
			}
			a.mu.Unlock()
			if clearedHostile {
				a.logger().Print("adaptive: strict TLS connection verified again; trust checks remain enforced")
			}
			return value, nil
		}
		if ctx.Err() != nil {
			a.mu.Unlock()
			return zero, ctx.Err()
		}
		a.lastFailure = runtimeFailureCategory(err)
		if a.tierFailures == nil {
			a.tierFailures = make(map[string]string)
		}
		failureName := a.tierName(idx)
		if idx < len(profileOrder) {
			failureName = "ws-tls"
		}
		a.tierFailures[failureName] = a.lastFailure
		if fatalUpstream(err) {
			a.mu.Unlock()
			return zero, err
		}
		logPinFailure := false
		if isPinFailure(err) {
			sawPin = true
			logPinFailure = !a.hostile
			a.setHostileLocked(true)
			a.tcpRetryAt = time.Now().Add(time.Minute + time.Duration(rand.Int63n(int64(15*time.Second))))
		}
		if isDNSError(err) {
			sawDNS = true
		}
		var keyRej *transport.SSHKeyRejectedError
		var rejectionPause time.Duration
		if errors.As(err, &keyRej) {
			rejectionPause = a.noteSSHRejectLocked()
		} else if idx >= len(profileOrder) {
			// One failure is enough to pause a blocked carrier briefly.
			// Periodic downward probes still detect network recovery.
			if a.tierCooldown == nil {
				a.tierCooldown = make(map[int]time.Time)
			}
			gap := time.Minute
			if idx == sshIdx {
				gap = 30 * time.Second
			}
			a.tierCooldown[idx] = time.Now().Add(gap + time.Duration(rand.Int63n(int64(gap)/4)))
		}
		lastErr = fmt.Errorf("tier %q: %w", a.tierName(idx), err)
		if idx == a.idx {
			a.failStreak++
		}
		a.mu.Unlock()
		if logPinFailure {
			a.logger().Print("adaptive: TLS pin verification failed (possible interception or stale trust); pins remain enforced, retry traffic is limited")
		}
		if rejectionPause > 0 {
			a.logger().Printf("adaptive: SSH rejected the device key; verify administrator approval and key reconciliation; retry paused for %s", rejectionPause.Round(time.Minute))
		}
	}
	if lastErr == nil {
		a.mu.Lock()
		lastErr = a.carrierUnavailableLocked()
		a.mu.Unlock()
	}
	if sawDNS {
		// Sinkholed entry hostname: go hostile-quiet instead of storming
		// redials at a dead name, and rotate entries when possible.
		a.RotateEntry("dns")
	}
	return zero, lastErr
}

// SetEntries installs the rotatable endpoint pool (primary first). The
// current entry becomes the live base; tier clients rebuild lazily.
func (a *Adaptive) SetEntries(entries []transport.WSTLSOptions) {
	if len(entries) == 0 {
		return
	}
	a.mu.Lock()
	a.entries = append([]transport.WSTLSOptions(nil), entries...)
	a.entryIdx = 0
	a.base = entries[0]
	a.invalidateClientsLocked()
	a.mu.Unlock()
}

// RotateEntry advances to the next endpoint (DNS death, shaping verdict).
// Returns false with a single entry (nothing to rotate to â€” thin mode and
// hostile quiet are the only responses left).
func (a *Adaptive) RotateEntry(reason string) bool {
	a.mu.Lock()
	if len(a.entries) < 2 {
		a.mu.Unlock()
		return false
	}
	a.entryIdx = (a.entryIdx + 1) % len(a.entries)
	a.base = a.entries[a.entryIdx]
	a.idx = 0
	a.failStreak = 0
	a.lastProbe = time.Time{}
	a.tcpRetryAt = time.Time{}
	a.hostile = false // strict pins are retried against the newly selected entry
	a.tierCooldown = nil
	a.sshCooldown = time.Time{}
	a.invalidateClientsLocked()
	addr := a.base.ServerAddr
	setHostileMode(false)
	a.mu.Unlock()
	a.logger().Printf("adaptive: rotating entry (%s) -> %s", reason, addr)
	return true
}

// EntryCount reports the pool size (for status output).
func (a *Adaptive) EntryCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) == 0 {
		return 1
	}
	return len(a.entries)
}

// isDNSError reports name-resolution failures (the sinkhole tell): the
// entry hostname does not resolve at all, as opposed to refusing or
// resetting connections.
func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return true
	}
	return strings.Contains(err.Error(), "no such host")
}

// Reset drops the client back to the fastest tier immediately: slow-start
// probing, failure streaks and the re-probe cool-off are cleared. Used when
// the panel reports approval â€” recovery must not wait out a 10-minute
// cool-off sitting on a degraded tier.
func (a *Adaptive) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Approval may have installed the key the ssh tier was refused for:
	// clear the backoff even in fixed-profile mode.
	a.sshRejects = 0
	a.sshCooldown = time.Time{}
	a.tierCooldown = nil
	a.tcpRetryAt = time.Time{}
	a.generation++ // an old refusal cannot undo this reviewed approval reset
	if !a.auto {
		return
	}
	a.idx = 0
	a.failStreak = 0
	a.lastProbe = time.Time{}
}

// SetHostile latches (or clears) hostile-network mode. While latched the
// client locks onto stealth shaping and stretches its beacons; the SSH tier
// hides unless AllowHostileSSH. Latched automatically on pin failures,
// cleared on the first clean ws-tls dial.
func (a *Adaptive) SetHostile(on bool) {
	a.mu.Lock()
	changed := a.hostile != on
	a.setHostileLocked(on)
	if on && a.tcpRetryAt.IsZero() {
		a.tcpRetryAt = time.Now().Add(time.Minute)
	}
	a.mu.Unlock()
	if changed {
		if on {
			a.logger().Printf("adaptive: TLS pin verification failed (possible interception or stale trust); pins remain enforced, retry traffic is limited")
		} else {
			a.logger().Printf("adaptive: clean network - hostile mode off")
		}
	}
}

// Caller holds a.mu; publishing the process flag inside the same critical
// section prevents a stale dial from racing a completed network reset.
func (a *Adaptive) setHostileLocked(on bool) {
	changed := a.hostile != on
	a.hostile = on
	if on && a.auto && a.idx < len(profileOrder)-1 {
		a.idx = len(profileOrder) - 1 // lock stealth shaping
	}
	if on && changed {
		a.lastProbe = time.Now()
	}
	setHostileMode(on)
	if !on {
		a.tcpRetryAt = time.Time{}
	}
}

// noteSSHReject applies the ssh-tier backoff: the server refused this
// device's key. Two consecutive rejections (one could be an approval
// race) pause the tier for a jittered cooldown, so a dead key stops
// costing every request — and stops presenting a failed login to the
// server dozens of times a minute, which is exactly what a credential
// attack looks like from its side.
func (a *Adaptive) noteSSHReject(err *transport.SSHKeyRejectedError) {
	a.mu.Lock()
	d := a.noteSSHRejectLocked()
	a.mu.Unlock()
	if d > 0 {
		a.logger().Printf("adaptive: %v - pausing the ssh tier for %s", err, d.Round(time.Minute))
	}
}

func (a *Adaptive) noteSSHRejectLocked() time.Duration {
	now := time.Now()
	a.sshRejects++
	if a.sshRejects < 2 || now.Before(a.sshCooldown) {
		return 0
	}
	d := sshRejectCooldown + time.Duration(rand.Int63n(int64(sshRejectCooldown)/5))
	a.sshCooldown = now.Add(d)
	return d
}

// isPinFailure reports certificate-pin rejections (the MITM tell), as
// opposed to unreachable hosts or refused tunnels.
func isPinFailure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "fingerprint mismatch") ||
		strings.Contains(s, "certificate is not trusted") ||
		strings.Contains(s, "unknown authority")
}

// Current reports the active tier name (for status output).
func (a *Adaptive) Current() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tierName(a.idx)
}

// CtrlExchange runs one in-band control exchange on the current tier's
// client (see control.go).
func (a *Adaptive) CtrlExchange(ctx context.Context, req protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
	response, err := adaptiveAttempt(a, ctx, func(cl *Client) (*protocol.CtrlResponse, error) {
		return cl.CtrlExchange(ctx, req)
	})
	if err == nil && response != nil && response.OK && req.Op == "status" {
		a.mu.Lock()
		a.lastAdmission = response.Status
		a.mu.Unlock()
	}
	return response, err
}

// AddPin appends a rotation pin to the base config and every entry, then
// drops the cached tier clients so new dials verify against it. Returns
// true when anything changed.
func (a *Adaptive) AddPin(fp string) bool {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return false
	}
	if _, err := transport.ParseFingerprint(fp); err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	if !pinKnown(a.base.Fingerprint, a.base.Fingerprints, fp) {
		a.base.Fingerprints = append(a.base.Fingerprints, fp)
		changed = true
	}
	for i := range a.entries {
		e := &a.entries[i]
		if !pinKnown(e.Fingerprint, e.Fingerprints, fp) {
			e.Fingerprints = append(e.Fingerprints, fp)
			changed = true
		}
	}
	if changed {
		a.invalidateClientsLocked()
		a.tierCooldown = nil
		a.tcpRetryAt = time.Time{}
		a.lastProbe = time.Time{} // trusted pin rotation warrants an immediate clean-path probe
	}
	return changed
}

func (a *Adaptive) invalidateClientsLocked() {
	a.generation++
	a.verifiedAt = time.Time{}
	a.pruneRetiredLocked()
	for _, cl := range a.clients {
		cl.Drain()
		a.retiredClients = append(a.retiredClients, cl)
	}
	a.clients = nil
}

var ErrNetworkChanged = errors.New("client: network or carrier configuration changed during setup; retry on the current network")

// ConnectionVerified reports observed authenticated activity, not listener
// readiness or a guarantee that arbitrary applications can use their proxy.
func (a *Adaptive) ConnectionVerified() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.closed && !a.verifiedAt.IsZero()
}

type CarrierUnavailableError struct {
	RetryAt time.Time
	Failure string
}

func (e *CarrierUnavailableError) Error() string {
	return "client: no carrier currently available; previous failure: " + e.Failure + "; failed carriers are cooling down (strict trust checks remain enabled)"
}

func (a *Adaptive) carrierUnavailableLocked() error {
	retry := a.tcpRetryAt
	for _, candidate := range a.tierCooldown {
		if candidate.After(time.Now()) && (retry.IsZero() || candidate.Before(retry)) {
			retry = candidate
		}
	}
	if a.sshCooldown.After(time.Now()) && (retry.IsZero() || a.sshCooldown.Before(retry)) {
		retry = a.sshCooldown
	}
	failure := a.lastFailure
	if failure == "" {
		failure = "connection-or-authority"
	}
	return &CarrierUnavailableError{RetryAt: retry, Failure: failure}
}

func (a *Adaptive) pruneRetiredLocked() {
	kept := a.retiredClients[:0]
	for _, cl := range a.retiredClients {
		if cl.DrainComplete() {
			select {
			case <-cl.startClose():
				continue
			default:
				kept = append(kept, cl)
			}
		} else {
			kept = append(kept, cl)
		}
	}
	a.retiredClients = kept
}

func (a *Adaptive) Close() error {
	a.mu.Lock()
	a.closed = true
	clients := a.clients
	retired := a.retiredClients
	a.clients = nil
	a.retiredClients = nil
	a.mu.Unlock()
	for _, cl := range clients {
		_ = cl.Close()
	}
	for _, cl := range retired {
		_ = cl.Close()
	}
	return nil
}

// pinKnown reports whether fp is already accepted (primary or rotation set).
func pinKnown(primary string, extra []string, fp string) bool {
	if strings.EqualFold(strings.TrimSpace(primary), fp) {
		return true
	}
	for _, p := range extra {
		if strings.EqualFold(strings.TrimSpace(p), fp) {
			return true
		}
	}
	return false
}

// Probe measures tunnel setup latency on the current tier (transport dial +
// handshake), then tears the connection down. Used for health telemetry.
func (a *Adaptive) Probe(ctx context.Context) (time.Duration, error) {
	return adaptiveAttempt(a, ctx, func(cl *Client) (time.Duration, error) {
		return cl.ProbeSession(ctx)
	})
}

// OpenUDPRelay returns a UDP relay stream using the currently selected
// profile. It implements proxy.UDPDialer.
func (a *Adaptive) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	return adaptiveAttempt(a, ctx, func(cl *Client) (net.Conn, error) {
		return cl.OpenUDPRelay(ctx)
	})
}

// Throughput probe defaults: a small sample from a stock speedtest file.
// 2 MB is enough to separate shaper-flat throughput from bursty congestion
// while costing ~70 Kbps averaged over a 4-minute cadence.
//
// DefaultProbeURLs: public bulk-download endpoints, one picked per probe so
// no single host sees a metronomic 2 MB pull every four minutes. All serve
// large files and honor Range requests.
var DefaultProbeURLs = []string{
	"https://proof.ovh.net/files/100Mb.dat",
	"https://speed.cloudflare.com/__down?bytes=104857600",
	"https://speedtest.tele2.net/100MB.zip",
}

// DefaultProbeURL mirrors the first pool entry (kept for compatibility).
const DefaultProbeURL = "https://proof.ovh.net/files/100Mb.dat"

const DefaultProbeSampleBytes = 2 << 20

// shapedFloorBps: sustained goodput under ~768 Kbps with a healthy handshake
// reads as shaper-capped, not congested (congestion jitters and recovers;
// shapers hold a flat ceiling indefinitely).
const shapedFloorBps = 96 << 10

// ProbeThroughput fetches a sample through the tunnel, returning handshake
// latency and sustained goodput. Splitting setup (TTFB) from transfer rate
// is the whole diagnosis: fast setup + flat low throughput is the shaper
// signature, while slow setup points at the path rather than a cap.
func (a *Adaptive) ProbeThroughput(ctx context.Context) (ttfb time.Duration, bps float64, err error) {
	u := a.ProbeURL
	if u == "" {
		u = DefaultProbeURLs[rand.Intn(len(DefaultProbeURLs))]
	}
	n := a.ProbeSampleBytes
	if n <= 0 {
		n = DefaultProbeSampleBytes
	}
	pu, err := url.Parse(u)
	if err != nil {
		return 0, 0, err
	}
	if (pu.Scheme != "http" && pu.Scheme != "https") || pu.Hostname() == "" || pu.User != nil || n > 64<<20 {
		return 0, 0, errors.New("client: invalid throughput probe URL or sample size")
	}
	tr := &http.Transport{
		DialContext: func(dctx context.Context, network, hostPort string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(hostPort)
			if err != nil {
				return nil, err
			}
			pnum, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}
			addr, err := protocol.ParseAddress(host, pnum)
			if err != nil {
				return nil, err
			}
			return a.DialTunnel(dctx, addr)
		},
		DisableCompression:     true,
		DisableKeepAlives:      true,
		TLSClientConfig:        a.probeTLSConfig,
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 3 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", transport.BrowserUA)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Range", "bytes=0-"+strconv.FormatInt(n-1, 10))
	t0 := time.Now()
	// HTTPS targets need an inner TLS handshake, not plaintext HTTP on :443.
	// net/http also checks status and decodes chunked bodies correctly.
	resp, err := cl.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, 0, fmt.Errorf("client: throughput probe returned %s", resp.Status)
	}
	ttfb = time.Since(t0)
	bodyStart := time.Now()
	got, err := io.CopyN(io.Discard, resp.Body, n)
	if err != nil {
		return 0, 0, err
	}
	return ttfb, float64(got) / time.Since(bodyStart).Seconds(), nil
}

// probeRequest builds the plain-HTTP request the throughput probe sends
// through the tunnel. The User-Agent must match the tunnel's version story
// (transport.BrowserUA — the old Chrome/126 string contradicted the
// Chrome/133 hello on the same flow), and the Range header frames the fetch
// as an ordinary resumable download.
func probeRequest(uri, host string, sampleBytes int64) string {
	return "GET " + uri + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Connection: close\r\n" +
		"Range: bytes=0-" + strconv.FormatInt(sampleBytes-1, 10) + "\r\n" +
		"User-Agent: " + transport.BrowserUA + "\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"\r\n"
}

// isShaped reports the shaper signature: healthy handshake, flat starved
// transfer. Anything else (slow setup, errors) is a different problem.
func isShaped(ttfb time.Duration, bps float64) bool {
	return ttfb < 2*time.Second && bps > 0 && bps < shapedFloorBps
}
