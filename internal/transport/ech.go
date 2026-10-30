// ech.go: Encrypted Client Hello (draft-ietf-tls-esni) support.
//
// ECH hides the REAL server name inside a TLS 1.3 ClientHello: the visible
// SNI is a cover name (the ECHConfig's public_name, e.g. cloudflare-ech.com)
// while the inner ClientHello — carrying the actual hostname — is HPKE-
// encrypted. The config lives in the hostname's HTTPS DNS record as an
// ECHConfigList, published by the CDN front (Cloudflare enables it for
// eligible zones automatically), which this file fetches over DoH from
// public resolvers.
//
// Threat model & guarantees:
//   - ECH defeats passive/SNI-based classification and blocking on
//     networks that do NOT intercept TLS: the censor never sees our
//     hostname. On intercepting networks the pin check still governs
//     trust — ECH changes nothing there (full-MITM is handled by the
//     h3/ssh tiers as before).
//   - A poisoned or stale ECH config can only cause a REJECTION, never
//     interception: the pinned certificate check remains the trust anchor
//     (the outer hello is pin-checked through uTLS's rejection callback).
//   - Fail-open: a rejected ECH attempt closes the socket, backs the
//     provider off, and retries once over a fresh socket WITHOUT ECH —
//     connectivity never depends on ECH succeeding.
package transport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DefaultECHDoH lists the public DoH resolvers consulted for HTTPS DNS
// records, in order. Response poisoning cannot compromise the tunnel (see
// the package comment): a bad config only causes rejection + fallback.
var DefaultECHDoH = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
}

// errNoECH reports a well-formed answer that simply carries no ECH config
// (the host is not ECH-enabled yet) — a normal state, retried rarely.
var errNoECH = errors.New("transport: no ECHConfigList published for host")

// dohClient fetches DNS answers over HTTPS. Short timeout: ECH is an
// enhancement, never a startup dependency.
var dohClient = &http.Client{Timeout: 8 * time.Second}

// echCacheFile is the on-disk cache format (survives client restarts so a
// restart does not refetch or lose ECH).
type echCacheFile struct {
	Host      string    `json:"host"`
	List      string    `json:"list"` // std base64 of the ECHConfigList
	FetchedAt time.Time `json:"fetched_at"`
}

// ECHProvider supplies the current ECHConfigList for one hostname. It
// loads a disk cache at Start, refreshes over DoH in the background
// (honoring the DNS TTL, clamped to [1h, 24h]), and backs off on
// rejections. ConfigFor/RejectedFor are host-gated so the same hooks can
// be installed on transports dialing other hosts (fallback entries) —
// those simply get nil (no ECH) until a provider exists for them.
type ECHProvider struct {
	host      string
	cachePath string
	doh       []string
	logf      func(format string, v ...any)

	// fetchFn is swappable for tests.
	fetchFn func(ctx context.Context, host string, doh []string) ([]byte, time.Duration, error)

	mu         sync.Mutex
	list       []byte
	fetchedAt  time.Time
	nextTry    time.Time
	backoff    time.Duration
	rejections int
	started    bool
}

// NewECHProvider builds a provider for host. cachePath may be empty
// (memory-only). doh empty = DefaultECHDoH. logf nil = silent.
func NewECHProvider(host, cachePath string, doh []string, logf func(format string, v ...any)) *ECHProvider {
	if len(doh) == 0 {
		doh = DefaultECHDoH
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ECHProvider{
		host:      strings.TrimSpace(host),
		cachePath: cachePath,
		doh:       doh,
		logf:      logf,
		fetchFn:   fetchECHConfig,
	}
}

// Host reports the hostname this provider serves (for logging/status).
func (p *ECHProvider) Host() string { return p.host }

// Start loads the disk cache and launches the background refresh loop.
// Idempotent; ctx cancellation stops the loop.
func (p *ECHProvider) Start(ctx context.Context) {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()

	p.loadCache()
	go p.loop(ctx)
}

// ConfigFor returns the current ECHConfigList when serverName is this
// provider's host (nil otherwise, and nil until a config is known).
// Suitable as a transport-wide hook: dials for other hosts get no ECH.
func (p *ECHProvider) ConfigFor(serverName string) []byte {
	if serverName != p.host {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.list
}

// RejectedFor reports an ECH rejection observed on a dial to serverName
// (a no-op for other hosts): the config is dropped and refetched after a
// jittered backoff, so a rotated/invalid config heals without hammering.
func (p *ECHProvider) RejectedFor(serverName string) {
	if serverName != p.host {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.list = nil
	p.rejections++
	backoff := 5 * time.Minute << (p.rejections - 1) // 5m, 10m, 20m, …
	if backoff > 2*time.Hour {
		backoff = 2 * time.Hour
	}
	p.nextTry = time.Now().Add(backoff + jitterDur(backoff/4))
	p.logf("ech: config rejected for %s — backing off %s", p.host, backoff.Round(time.Minute))
}

// loop refreshes in the background on the provider's schedule.
func (p *ECHProvider) loop(ctx context.Context) {
	for {
		p.mu.Lock()
		next := p.nextTry
		p.mu.Unlock()
		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		p.fetchNow(ctx)
	}
}

// fetchNow runs one fetch attempt and reschedules (used by loop; tests
// call it directly).
func (p *ECHProvider) fetchNow(ctx context.Context) {
	fctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	list, ttl, err := p.fetchFn(fctx, p.host, p.doh)

	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		if errors.Is(err, errNoECH) {
			// Not ECH-enabled (yet): rare retries, no backoff noise.
			p.nextTry = time.Now().Add(6*time.Hour + jitterDur(time.Hour))
			p.logf("ech: %s publishes no ECH config (retrying in ~6h)", p.host)
			return
		}
		if p.backoff == 0 {
			p.backoff = 15 * time.Minute
		} else if p.backoff < 6*time.Hour {
			p.backoff *= 2
		}
		p.nextTry = time.Now().Add(p.backoff + jitterDur(p.backoff/4))
		p.logf("ech: fetch for %s failed: %v (next try ~%s)", p.host, err, p.backoff.Round(time.Minute))
		return
	}
	p.backoff = 0
	p.rejections = 0
	if ttl < time.Hour {
		ttl = time.Hour
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	p.nextTry = time.Now().Add(ttl + jitterDur(ttl/8))
	if len(p.list) == 0 || !equalBytes(p.list, list) {
		p.logf("ech: %s config loaded (%d bytes)", p.host, len(list))
	}
	p.list = list
	p.fetchedAt = time.Now()
	p.persistLocked()
}

// loadCache seeds the provider from disk (if the cache is for this host)
// and schedules the first refresh.
func (p *ECHProvider) loadCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.nextTry.IsZero() {
		p.nextTry = time.Now().Add(30*time.Second + jitterDur(time.Minute))
	}
	if p.cachePath == "" {
		return
	}
	data, err := os.ReadFile(p.cachePath)
	if err != nil {
		return
	}
	var c echCacheFile
	if json.Unmarshal(data, &c) != nil || c.Host != p.host || c.List == "" {
		return
	}
	list, err := base64.StdEncoding.DecodeString(c.List)
	if err != nil || len(list) == 0 {
		return
	}
	p.list = list
	p.fetchedAt = c.FetchedAt
	// Fresh cache: push the first refresh out; stale: refresh soon.
	age := time.Since(c.FetchedAt)
	switch {
	case age < 12*time.Hour:
		p.nextTry = time.Now().Add(20*time.Minute + jitterDur(20*time.Minute))
	default:
		p.nextTry = time.Now().Add(2*time.Minute + jitterDur(3*time.Minute))
	}
	p.logf("ech: %s config restored from cache (%d bytes)", p.host, len(list))
}

// persistLocked writes the cache file (caller holds mu).
func (p *ECHProvider) persistLocked() {
	if p.cachePath == "" || len(p.list) == 0 {
		return
	}
	if dir := filepath.Dir(p.cachePath); dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	data, err := json.Marshal(echCacheFile{
		Host:      p.host,
		List:      base64.StdEncoding.EncodeToString(p.list),
		FetchedAt: p.fetchedAt,
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(p.cachePath, data, 0o600)
}

// fetchECHConfig queries the DoH resolvers in order and returns the first
// ECH config found, with the answer's TTL.
func fetchECHConfig(ctx context.Context, host string, doh []string) ([]byte, time.Duration, error) {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t") {
		return nil, 0, fmt.Errorf("transport: invalid ECH host %q", host)
	}
	var lastErr error
	for _, endpoint := range doh {
		list, ttl, err := dohHTTPSECH(ctx, endpoint, host)
		if err == nil && len(list) > 0 {
			return list, ttl, nil
		}
		if errors.Is(err, errNoECH) {
			lastErr = err
			continue
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errNoECH
	}
	return nil, 0, lastErr
}

// dohHTTPSECH performs one RFC 8484 DoH query for the host's HTTPS record
// and extracts the ECH SvcParam.
func dohHTTPSECH(ctx context.Context, endpoint, host string) ([]byte, time.Duration, error) {
	name := host
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, 0, fmt.Errorf("transport: bad dns name %q: %w", host, err)
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  dnsmessage.TypeHTTPS,
			Class: dnsmessage.ClassINET,
		}},
	}
	body, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("transport: doh %s: HTTP %d", endpoint, resp.StatusCode)
	}
	var buf [64 << 10]byte
	n, err := resp.Body.Read(buf[:])
	if err != nil && n == 0 {
		return nil, 0, err
	}
	return parseDoHHTTPSResponse(buf[:n], id)
}

// parseDoHHTTPSResponse unpacks one DoH reply and returns the ECH param
// of its first HTTPS answer (any owner name: CNAME chains included).
func parseDoHHTTPSResponse(raw []byte, id uint16) ([]byte, time.Duration, error) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, 0, fmt.Errorf("transport: doh reply: %w", err)
	}
	if msg.Header.ID != id {
		return nil, 0, errors.New("transport: doh reply id mismatch")
	}
	for _, ans := range msg.Answers {
		https, ok := ans.Body.(*dnsmessage.HTTPSResource)
		if !ok {
			continue
		}
		val, ok := https.GetParam(dnsmessage.SVCParamECH)
		if !ok || len(val) == 0 {
			continue
		}
		ttl := time.Duration(ans.Header.TTL) * time.Second
		return append([]byte(nil), val...), ttl, nil
	}
	return nil, 0, errNoECH
}

// ---- small helpers ----

func jitterDur(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return d / 2
	}
	n := binary.BigEndian.Uint64(b[:]) % uint64(d+1)
	return time.Duration(n)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- process-wide default hooks (control-plane parity) ----

var (
	defECHMu       sync.Mutex
	defECHList     func(serverName string) []byte
	defECHRejected func(serverName string)
)

// SetDefaultECH installs process-wide ECH hooks used by pinned clients
// that were not given their own. The control plane (status polls, health
// reports) must tell the same SNI story as the tunnel — a plain-SNI poll
// next to an ECH tunnel re-exposes the hostname the tunnel just hid.
// Call once at startup; pass nil, nil to clear (tests).
func SetDefaultECH(list func(serverName string) []byte, rejected func(serverName string)) {
	defECHMu.Lock()
	defECHList, defECHRejected = list, rejected
	defECHMu.Unlock()
}

func defaultECHHooks() (func(string) []byte, func(string)) {
	defECHMu.Lock()
	defer defECHMu.Unlock()
	if defECHList == nil && defECHRejected == nil {
		return nil, nil
	}
	list := defECHList
	rejected := defECHRejected
	if list == nil {
		list = func(string) []byte { return nil }
	}
	if rejected == nil {
		rejected = func(string) {}
	}
	return list, rejected
}
