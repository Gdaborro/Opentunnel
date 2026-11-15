package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"opentunnel/internal/config"
	"opentunnel/internal/serverpool"
	"opentunnel/internal/transport"
)

const poolProbeTTL = 10 * time.Minute

type nodeRank struct {
	node    serverpool.Node
	latency time.Duration
}

// PoolSelector only probes nodes in an accepted profile, without credentials.
// Pool membership is verified over each node's own pinned TLS connection.
// Selection is latency-based, not geographic, and never changes operator trust.
type PoolSelector struct {
	profile  serverpool.Profile
	mu       sync.Mutex
	ranks    []nodeRank
	current  serverpool.Node
	probed   time.Time
	refresh  *poolRefresh
	probe    func(context.Context, serverpool.Node) (time.Duration, error)
	dialNode func(context.Context, context.Context, serverpool.Node, time.Duration) (net.Conn, error)
}

type poolRefresh struct {
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int
	err       error
	abandoned bool
}

func NewPoolSelector(p serverpool.Profile) (*PoolSelector, error) {
	if err := p.Verify(time.Now()); err != nil {
		return nil, err
	}
	// Own a deep copy; a caller cannot change pins/targets after validation.
	raw, _ := json.Marshal(p)
	var owned serverpool.Profile
	_ = json.Unmarshal(raw, &owned)
	s := &PoolSelector{profile: owned, current: owned.Nodes[0]}
	s.probe = func(ctx context.Context, node serverpool.Node) (time.Duration, error) {
		start := time.Now()
		if _, err := verifiedPoolInfo(ctx, owned, node); err != nil {
			return 0, err
		}
		return time.Since(start), nil
	}
	s.dialNode = s.connectNode
	return s, nil
}

func cloneNode(n serverpool.Node) serverpool.Node {
	n.Pins = append([]string(nil), n.Pins...)
	n.InnerTLSPins = append([]string(nil), n.InnerTLSPins...)
	return n
}

func (s *PoolSelector) Current() serverpool.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneNode(s.current)
}

func (s *PoolSelector) Refresh(ctx context.Context) error {
	for {
		retry, err := s.waitRefresh(ctx)
		if !retry {
			return err
		}
	}
}

func (s *PoolSelector) waitRefresh(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := s.profile.Verify(time.Now()); err != nil {
		return false, err
	}
	s.mu.Lock()
	if len(s.ranks) > 0 && time.Since(s.probed) < poolProbeTTL {
		s.mu.Unlock()
		return false, nil
	}
	job := s.refresh
	if job != nil && job.abandoned {
		// Join the old job's teardown before starting a new bounded job.
		// A new caller must not inherit another caller's cancellation or
		// create a second four-probe batch while the old one is stopping.
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-job.done:
			return true, nil
		}
	}
	if job == nil {
		// A caller owns its wait, not every other caller's refresh. Cancel
		// the bounded job only when its last waiter leaves.
		budget, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		job = &poolRefresh{done: make(chan struct{}), cancel: cancel}
		s.refresh = job
		go s.runRefresh(budget, job)
	}
	job.waiters++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		job.waiters--
		if job.waiters == 0 && s.refresh == job {
			job.abandoned = true
			job.cancel()
		}
		s.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-job.done:
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return false, job.err
	}
}

func (s *PoolSelector) runRefresh(budget context.Context, job *poolRefresh) {
	defer job.cancel()
	results := make(chan nodeRank, len(s.profile.Nodes))
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, node := range s.profile.Nodes {
		wg.Add(1)
		go func(n serverpool.Node) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-budget.Done():
				return
			}
			defer func() { <-slots }()
			probeCtx, stop := context.WithTimeout(budget, 3*time.Second)
			defer stop()
			d, err := s.probe(probeCtx, n)
			if err == nil && probeCtx.Err() == nil && d > 0 {
				results <- nodeRank{node: n, latency: d}
			}
		}(node)
	}
	wg.Wait()
	close(results)
	var ranks []nodeRank
	for rank := range results {
		ranks = append(ranks, rank)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.refresh = nil; close(job.done) }()
	if len(ranks) == 0 || errors.Is(budget.Err(), context.Canceled) {
		// Do not reuse stale reachability after a failed refresh.
		s.ranks, s.probed = nil, time.Time{}
		job.err = errors.New("no verified node is currently reachable in the selected pool")
		if budget.Err() != nil {
			job.err = budget.Err()
		}
		return
	}
	sort.SliceStable(ranks, func(i, j int) bool {
		if ranks[i].latency == ranks[j].latency {
			return ranks[i].node.ID < ranks[j].node.ID
		}
		return ranks[i].latency < ranks[j].latency
	})
	// Keep a healthy selected node unless the improvement is meaningful.
	// This avoids flapping on tiny timing differences between probes.
	if !s.probed.IsZero() {
		for i := range ranks {
			if ranks[i].node.ID == s.current.ID && ranks[i].latency-ranks[0].latency < max(25*time.Millisecond, ranks[i].latency/5) {
				chosen := ranks[i]
				ranks = append([]nodeRank{chosen}, append(ranks[:i:i], ranks[i+1:]...)...)
				break
			}
		}
	}
	s.ranks, s.current, s.probed = ranks, ranks[0].node, time.Now()
}

func (s *PoolSelector) Profile() serverpool.Profile {
	p := s.profile
	p.Nodes = make([]serverpool.Node, len(s.profile.Nodes))
	for i, n := range s.profile.Nodes {
		p.Nodes[i] = cloneNode(n)
	}
	return p
}

func (s *PoolSelector) Transport(timeout time.Duration) transport.Transport {
	return &poolTransport{selector: s, timeout: timeout}
}

type poolTransport struct {
	selector *PoolSelector
	timeout  time.Duration
}

func (*poolTransport) Name() string { return "ws-tls" }

func (p *poolTransport) Dial(ctx context.Context) (net.Conn, error) {
	return p.DialSetup(ctx, ctx)
}

func (p *poolTransport) DialSetup(setup, lifetime context.Context) (net.Conn, error) {
	budget, cancel := context.WithTimeout(setup, minPositiveDuration(p.timeout, 15*time.Second))
	defer cancel()
	if err := p.selector.Refresh(budget); err != nil {
		return nil, err
	}
	p.selector.mu.Lock()
	ranks := append([]nodeRank(nil), p.selector.ranks...)
	current := p.selector.current.ID
	p.selector.mu.Unlock()
	// A recently successful failover remains the first candidate.
	for i := range ranks {
		if ranks[i].node.ID == current {
			ranks[0], ranks[i] = ranks[i], ranks[0]
			break
		}
	}
	for _, rank := range ranks {
		if err := budget.Err(); err != nil {
			return nil, err
		}
		n := rank.node
		if !p.selector.profile.ContainsNode(n) {
			return nil, errors.New("selected data node is not in the accepted profile")
		}
		candidate, stop := context.WithTimeout(budget, minPositiveDuration(p.timeout, 4*time.Second))
		c, err := p.selector.dialNode(candidate, lifetime, n, p.timeout)
		candidateErr := candidate.Err()
		stop()
		if err != nil || candidateErr != nil || c == nil {
			if c != nil {
				transport.AbortSetup(c)
			}
			if err := setup.Err(); err != nil {
				return nil, err
			}
			if err := lifetime.Err(); err != nil {
				return nil, err
			}
			p.selector.failed(n.ID)
			continue
		}
		if err := lifetime.Err(); err != nil {
			transport.AbortSetup(c)
			return nil, err
		}
		p.selector.mu.Lock()
		p.selector.current = n
		p.selector.mu.Unlock()
		return c, nil
	}
	if err := budget.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("all verified nodes in the selected pool failed transport setup; no other operator was tried")
}

func (s *PoolSelector) failed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.ranks {
		if s.ranks[i].node.ID == id {
			s.ranks = append(s.ranks[:i:i], s.ranks[i+1:]...)
			break
		}
	}
	if len(s.ranks) == 0 {
		s.probed = time.Time{}
	}
}

func (s *PoolSelector) connectNode(setup, lifetime context.Context, n serverpool.Node, timeout time.Duration) (net.Conn, error) {
	tr := transport.NewWSTLS(transport.WSTLSOptions{ServerAddr: n.DialAddr(), ServerName: n.ServerName(), HTTPAuthority: n.Address, WSPath: n.WSPath, DisableLegacyFallback: true,
		Fingerprint: n.Pins[0], Fingerprints: append([]string(nil), n.Pins...), ChromeHello: true, DialTimeout: minPositiveDuration(timeout, 4*time.Second)})
	c, err := tr.(transport.SetupDialer).DialSetup(setup, lifetime)
	if err != nil {
		return nil, err
	}
	if len(n.InnerTLSPins) == 0 {
		return c, nil
	}
	wrapped, err := withScopedInnerTLS(&oneConnTransport{conn: c}, n.InnerTLSPins, s.profile.ID)
	if err != nil {
		transport.AbortSetup(c)
		return nil, err
	}
	inner, err := wrapped.(transport.SetupDialer).DialSetup(setup, lifetime)
	if err != nil {
		transport.AbortSetup(c)
		return nil, err
	}
	return inner, nil
}

func minPositiveDuration(d, maxDuration time.Duration) time.Duration {
	if d <= 0 || d > maxDuration {
		return maxDuration
	}
	return d
}

type oneConnTransport struct{ conn net.Conn }

func (*oneConnTransport) Name() string                             { return "ws-tls" }
func (t *oneConnTransport) Dial(context.Context) (net.Conn, error) { return t.conn, nil }

func nodeHTTP(n serverpool.Node, timeout time.Duration) (*http.Client, error) {
	if len(n.Pins) == 0 {
		return nil, errors.New("node TLS pins are required")
	}
	return transport.NewPinnedHTTPClient(transport.PinnedHTTPOptions{DialAddr: n.DialAddr(), ServerName: n.ServerName(),
		Fingerprint: n.Pins[0], Fingerprints: n.Pins, ChromeHello: true, Timeout: timeout})
}

func verifiedPoolInfo(ctx context.Context, p serverpool.Profile, n serverpool.Node) (serverpool.Info, error) {
	var info serverpool.Info
	if err := p.Verify(time.Now()); err != nil {
		return info, err
	}
	if !p.ContainsNode(n) {
		return info, errors.New("node is not in the accepted server profile")
	}
	cl, err := nodeHTTP(n, 3*time.Second)
	if err != nil {
		return info, err
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+n.Address+serverpool.InfoPath, nil)
	if err != nil {
		return info, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return info, errors.New("node could not be verified over pinned TLS")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, errors.New("node does not offer the selected pool enrollment contract")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return info, errors.New("node capability response oversized or incomplete")
	}
	if err := serverpool.DecodeStrict(raw, &info); err != nil || info.Version != 1 || info.PoolID != p.ID || info.AuthorityID != p.AuthorityID || info.LoginRequired != p.LoginRequired || !info.ApprovalRequired {
		return info, errors.New("verified node pool identity or approval/login policy differs from the accepted profile")
	}
	return info, nil
}

var ErrEnrollmentLoginRequired = errors.New("selected pool requires enrollment login; device approval remains required")
var ErrEnrollmentDenied = errors.New("pool enrollment refused; account or device eligibility requires operator review")

// EnrollmentCredentials exist only for this request. They are never stored in
// a profile, sent to redirects, or copied into later tunnel authentication.
type EnrollmentCredentials struct {
	Username string
	Password []byte
}

func requirePoolIdentity(scope, token string) (*deviceFile, error) {
	store, err := NewPoolTokenStore(scope)
	if err != nil {
		return nil, err
	}
	device, err := store.LoadOrCreate()
	if err != nil {
		return nil, err
	}
	if device.Token != token {
		return nil, errors.New("device identity does not belong to the selected operator; no token sent")
	}
	return device, nil
}

func EnrollPool(ctx context.Context, cfg *config.ClientConf, device *deviceFile, credentials *EnrollmentCredentials) error {
	if cfg.Pool == nil || cfg.PoolNode == nil || cfg.Insecure || cfg.AllowUntrustedBootstrap {
		return errors.New("pool enrollment requires an explicitly trusted profile and verified node selection")
	}
	if err := cfg.Pool.Verify(time.Now()); err != nil {
		return err
	}
	node := cfg.PoolNode()
	if !cfg.Pool.ContainsNode(node) {
		return errors.New("enrollment node is not in the accepted profile; no credentials sent")
	}
	if _, err := verifiedPoolInfo(ctx, *cfg.Pool, node); err != nil {
		return err
	}
	store, err := NewPoolTokenStore(cfg.IdentityScope())
	if err != nil {
		return err
	}
	ownedDevice, err := store.LoadOrCreate()
	if err != nil {
		return err
	}
	if device == nil || device.Token != ownedDevice.Token || device.Fingerprint != ownedDevice.Fingerprint {
		return errors.New("enrollment identity does not belong to the selected operator")
	}
	pub, err := store.EnsureSSHKey()
	if err != nil {
		return err
	}
	body := struct {
		PoolID      string `json:"pool_id"`
		Token       string `json:"token"`
		Fingerprint string `json:"fingerprint"`
		DeviceName  string `json:"device_name"`
		SSHPubKey   string `json:"ssh_pubkey"`
		Username    string `json:"username,omitempty"`
		Password    string `json:"password,omitempty"`
	}{PoolID: cfg.Pool.ID, Token: device.Token, Fingerprint: device.Fingerprint, DeviceName: device.DeviceName, SSHPubKey: pub}
	if credentials != nil {
		if !cfg.Pool.LoginRequired {
			return errors.New("selected pool does not request a password; no credentials sent")
		}
		if len(credentials.Username) < 3 || len(credentials.Username) > 64 || len(credentials.Password) < 1 || len(credentials.Password) > 72 {
			return errors.New("enrollment credentials are invalid")
		}
		body.Username, body.Password = credentials.Username, string(credentials.Password)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return errors.New("enrollment request invalid")
	}
	defer clear(raw)
	cl, err := nodeHTTP(node, 12*time.Second)
	if err != nil {
		return err
	}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+node.Address+"/api/token/request", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := SignPoolHTTPRequest(req, raw, cfg.IdentityScope()); err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return errors.New("verified pool enrollment channel unavailable; credentials not retried to other nodes")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrEnrollmentLoginRequired
	case http.StatusConflict:
		return errRegistrationIdentityConflict
	case http.StatusForbidden:
		return ErrEnrollmentDenied
	case http.StatusOK:
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
		if err != nil || len(data) > 4096 {
			return errors.New("enrollment response oversized or incomplete")
		}
		var result struct {
			Status string `json:"status"`
		}
		if err := serverpool.DecodeStrict(data, &result); err != nil {
			return errors.New("pool enrollment response invalid")
		}
		switch result.Status {
		case "pending", "approved", "expired", "kicked", "banned":
			return nil
		}
		return errors.New("pool returned unknown enrollment state")
	default:
		return errors.New("pool enrollment temporarily unavailable")
	}
}
