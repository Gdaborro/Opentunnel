package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
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

// H3TierName is the HTTP/3 tier: QUIC to :443 survives TLS interception
// (middleboxes cannot re-sign what they cannot terminate), sits between
// the ws-tls profiles and the ssh last resort, and carries bulk traffic
// on hostile networks so SSH doesn't have to.
const H3TierName = "h3"

// tierCount returns how many tiers exist including the optional h3 and
// ssh fallbacks. In hostile mode the SSH tier is hidden unless explicitly
// allowed: an all-day SSH session is the most conspicuous state on an
// intercepting net. The h3 tier stays: it reads as ordinary HTTP/3.
func (a *Adaptive) tierCount() int {
	n := len(profileOrder)
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
	if a.h3Fallback != nil && idx == len(profileOrder) {
		return H3TierName
	}
	return SshTierName
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
	mu          sync.Mutex
	token       string
	base        transport.WSTLSOptions
	idx         int // index into profileOrder
	auto        bool
	lastProbe   time.Time
	ttfbBudget  time.Duration
	dialTimeout time.Duration
	factory     func(a *Adaptive, idx int) *Client
	Logger      *log.Logger // optional; nil = log.Default()
	mux         bool        // multiplexing requested by config
	failStreak  int         // consecutive failures on current tier

	// clients caches one Client per tier so every browser connection reuses
	// the tier's warm mux pool instead of paying a full transport handshake
	// (TCP + TLS/SSH + auth) per request. Without this, page-load bursts
	// mint hundreds of handshakes and melt a small relay.
	clients map[int]*Client

	// transportBuilder lets configs swap the underlying transport per
	// profile (e.g. ssh). Defaults to ws-tls with Chrome hello above fast.
	transportBuilder func(profile string) transport.Transport

	// sshFallback, when set, adds a final last-resort tier that tunnels
	// inside real SSH — used when every ws-tls tier is intercepted.
	sshFallback func() transport.Transport

	// h3Fallback, when set, adds the HTTP/3 tier between the ws-tls
	// profiles and ssh: QUIC cannot be transparently intercepted, so the
	// pinned handshake reaches the relay untouched on MITM networks.
	h3Fallback func() transport.Transport

	// AllowHostileSSH permits the SSH tier while hostile mode is active
	// (TLS-intercepting network). Default true preserves connectivity;
	// set false to forbid the conspicuous SSH fallback on hostile nets.
	AllowHostileSSH bool

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
	a.clients = nil // rebuilt lazily with the new setting
}

// EnableSSHFallback adds the ssh last-resort tier to the ladder.
func (a *Adaptive) EnableSSHFallback(builder func() transport.Transport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sshFallback = builder
	a.clients = nil // rebuilt lazily with the new setting
}

// EnableH3 adds the HTTP/3 tier to the ladder (between ws-tls and ssh).
func (a *Adaptive) EnableH3(builder func() transport.Transport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.h3Fallback = builder
	a.clients = nil // rebuilt lazily with the new setting
}

// UseTransportBuilder overrides how per-profile transports are constructed.
func (a *Adaptive) UseTransportBuilder(f func(profile string) transport.Transport) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.transportBuilder = f
	a.clients = nil // rebuilt lazily with the new setting
}

func (a *Adaptive) logger() *log.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return log.Default()
}

func NewAdaptive(token string, base transport.WSTLSOptions, profile string, dialTimeout time.Duration) *Adaptive {
	a := &Adaptive{
		token:       token,
		base:        base,
		auto:        profile == "auto",
		ttfbBudget:  3 * time.Second,
		dialTimeout: dialTimeout,
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
	case a.h3Fallback != nil && idx == len(profileOrder):
		tr = a.h3Fallback()
	case a.sshFallback != nil:
		tr = a.sshFallback()
	default:
		opt := a.base
		opt.ChromeHello = true
		tr = transport.NewWSTLS(opt)
	}
	return NewWithOptions(tr, Options{
		Token:          a.token,
		DialTimeout:    a.dialTimeout,
		Profile:        "balanced", // under h3/ssh, mild padding; harmless elsewhere
		Mux:            a.mux,
		OnAuthRejected: a.OnAuthRejected,
	})
}

func (a *Adaptive) build(idx int) *Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.clients == nil {
		a.clients = make(map[int]*Client)
	}
	if cl, ok := a.clients[idx]; ok {
		return cl
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
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
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
	a.mu.Lock()
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
	a.mu.Unlock()

	order := []int{}
	if probeDown {
		order = append(order, 0)
	}
	for i := start; i < total; i++ {
		if probeDown && i == 0 {
			continue
		}
		order = append(order, i)
	}

	var lastErr error
	sawPin := false
	sawDNS := false
	for _, idx := range order {
		cl := a.build(idx)
		t0 := time.Now()
		conn, err := cl.DialTunnel(ctx, target)
		if err == nil {
			elapsed := time.Since(t0)
			clearedHostile := false
			a.mu.Lock()
			a.failStreak = 0
			if a.hostile && idx < len(profileOrder) {
				a.hostile = false // clean ws-tls dial: network changed
				clearedHostile = true
			}
			switch {
			case probeDown && idx == 0:
				a.idx = 0 // lower profile healthy again â€” stay fast
				a.logger().Printf("adaptive: fast profile healthy again â€” back to %q", ProfileFast)
			default:
				if idx > a.idx {
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
				a.SetHostile(false)
			}
			return conn, nil
		}
		if fatalUpstream(err) {
			return nil, err
		}
		if isPinFailure(err) {
			sawPin = true
		}
		if isDNSError(err) {
			sawDNS = true
		}
		a.mu.Lock()
		lastErr = fmt.Errorf("tier %q: %w", a.tierName(idx), err)
		if idx == a.idx {
			a.failStreak++
		}
		a.mu.Unlock()
	}
	if lastErr == nil {
		lastErr = errors.New("client: no tiers available")
	}
	if sawPin {
		a.SetHostile(true) // every ws tier hit pinning: TLS interception
	}
	if sawDNS {
		// Sinkholed entry hostname: go hostile-quiet instead of storming
		// redials at a dead name, and rotate entries when possible.
		a.SetHostile(true)
		a.RotateEntry("dns")
	}
	return nil, lastErr
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
	a.clients = nil
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
	a.clients = nil
	addr := a.base.ServerAddr
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
	a.hostile = on
	if on && a.auto && a.idx < len(profileOrder)-1 {
		a.idx = len(profileOrder) - 1 // lock stealth shaping
	}
	a.mu.Unlock()
	setHostileMode(on)
	if changed {
		if on {
			a.logger().Printf("adaptive: hostile network (TLS interception) â€” stealth locked, beacons stretched")
		} else {
			a.logger().Printf("adaptive: clean network â€” hostile mode off")
		}
	}
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
	a.mu.Lock()
	idx := a.idx
	a.mu.Unlock()
	return a.build(idx).CtrlExchange(ctx, req)
}

// AddPin appends a rotation pin to the base config and every entry, then
// drops the cached tier clients so new dials verify against it. Returns
// true when anything changed.
func (a *Adaptive) AddPin(fp string) bool {
	fp = strings.TrimSpace(fp)
	if fp == "" {
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
		a.clients = nil // rebuild transports with the extended pin set
	}
	return changed
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
	a.mu.Lock()
	idx := a.idx
	a.mu.Unlock()
	return a.build(idx).ProbeSession(ctx)
}

// OpenUDPRelay returns a UDP relay stream using the currently selected
// profile. It implements proxy.UDPDialer.
func (a *Adaptive) OpenUDPRelay(ctx context.Context) (net.Conn, error) {
	a.mu.Lock()
	idx := a.idx
	a.mu.Unlock()
	return a.build(idx).OpenUDPRelay(ctx)
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
	port := pu.Port()
	if port == "" {
		port = "443"
		if pu.Scheme == "http" {
			port = "80"
		}
	}
	pnum, err := strconv.Atoi(port)
	if err != nil || pnum < 1 || pnum > 65535 {
		return 0, 0, fmt.Errorf("client: bad probe port %q", port)
	}
	addr, err := protocol.ParseAddress(pu.Hostname(), pnum)
	if err != nil {
		return 0, 0, err
	}
	t0 := time.Now()
	conn, err := a.DialTunnel(ctx, addr)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, probeRequest(pu.RequestURI(), pu.Host, n)); err != nil {
		return 0, 0, err
	}
	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, 0, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	ttfb = time.Since(t0)
	bodyStart := time.Now()
	var got int64
	buf := make([]byte, 64*1024)
	for got < n {
		m := int64(len(buf))
		if m > n-got {
			m = n - got
		}
		k, err := io.ReadFull(br, buf[:m])
		got += int64(k)
		if err != nil {
			return 0, 0, err
		}
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
