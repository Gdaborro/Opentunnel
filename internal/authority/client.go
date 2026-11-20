package authority

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"opentunnel/internal/access"
	"opentunnel/internal/metrics"
	"opentunnel/internal/protocol"
	"opentunnel/internal/serverpool"
)

type ClientOptions struct {
	URL                         string
	PoolID, AuthorityID, NodeID string
	Certificate                 tls.Certificate
	Pins                        []string
	Timeout                     time.Duration
}

type Client struct {
	opt       ClientOptions
	http      *http.Client
	transport *http.Transport
}

func NewClient(opt ClientOptions) (*Client, error) {
	u, err := url.Parse(opt.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || !serverpool.ValidID(opt.PoolID) || !serverpool.ValidID(opt.AuthorityID) || !ValidNodeID(opt.NodeID) {
		return nil, errors.New("invalid explicit authority URL or node scope")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, errors.New("authority URL needs an explicit host and TLS port")
	}
	cfg, err := ClientTLS(opt.Certificate, u.Hostname(), opt.Pins)
	if err != nil {
		return nil, err
	}
	opt.URL = strings.TrimRight(opt.URL, "/")
	if opt.Timeout <= 0 || opt.Timeout > 5*time.Second {
		opt.Timeout = 3 * time.Second
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: cfg, ForceAttemptHTTP2: true, DialContext: (&net.Dialer{Timeout: opt.Timeout}).DialContext, TLSHandshakeTimeout: opt.Timeout, ResponseHeaderTimeout: opt.Timeout, MaxIdleConns: 32, MaxIdleConnsPerHost: 32, MaxConnsPerHost: 64, IdleConnTimeout: 60 * time.Second}
	return &Client{opt: opt, transport: tr, http: &http.Client{Transport: tr, Timeout: opt.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("authority redirect refused") }}}, nil
}

func (c *Client) Close() error           { c.transport.CloseIdleConnections(); return nil }
func (c *Client) CentralAuthority() bool { return true }

func (c *Client) call(parent context.Context, op string, request, response any) error {
	ctx, cancel := context.WithTimeout(parent, c.opt.Timeout)
	defer cancel()
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > MaxBody {
		return ErrDenied
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opt.URL+APIPath+op, bytes.NewReader(raw))
	if err != nil {
		return ErrUnavailable
	}
	c.stamp(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return sql.ErrNoRows
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusBadRequest {
		return ErrDenied
	}
	if resp.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil || len(body) > MaxResponse || serverpool.DecodeStrict(body, response) != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) stamp(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Otu-Node", c.opt.NodeID)
	req.Header.Set("X-Otu-Pool", c.opt.PoolID)
	req.Header.Set("X-Otu-Authority", c.opt.AuthorityID)
}

func (c *Client) Info(ctx context.Context) (serverpool.Info, error) {
	var info serverpool.Info
	err := c.call(ctx, "info", struct{}{}, &info)
	if err == nil && (info.PoolID != c.opt.PoolID || info.AuthorityID != c.opt.AuthorityID || !info.ApprovalRequired || !info.RequireChannelAuth || info.Version != serverpool.ChannelProfileVersion) {
		err = ErrDenied
	}
	return info, err
}

func (c *Client) AccessPolicy(token string) (access.Snapshot, error) {
	var p access.Snapshot
	err := c.call(context.Background(), "policy", TokenRequest{token}, &p)
	if err == nil && (p.PoolID != c.opt.PoolID || p.AuthorityID != c.opt.AuthorityID || !p.ChannelRequired) {
		err = ErrDenied
	}
	return p, err
}

func (c *Client) CheckToken(token string) (string, string, string, error) {
	p, err := c.AccessPolicy(token)
	return p.Status, p.Reason, p.Expires, err
}
func (c *Client) KnownPeer(token string) bool { _, err := c.AccessPolicy(token); return err == nil }
func (c *Client) SSHPubKey(token string) string {
	p, err := c.AccessPolicy(token)
	if err != nil {
		return ""
	}
	return p.PublicKey
}
func (c *Client) V5Seen(token string) bool {
	p, err := c.AccessPolicy(token)
	return err == nil && p.V5Seen
}
func (c *Client) MarkV5(string)                         {} // never an unchecked remote authentication write
func (c *Client) CommitV5(string, string, string) error { return ErrDenied }
func (c *Client) CommitAuthentication(token, generation, publicKey string, channel bool) error {
	var response OK
	if !channel {
		return ErrDenied
	}
	err := c.call(context.Background(), "authenticate", AuthRequest{token, generation, publicKey, true}, &response)
	if err == nil && !response.OK {
		err = ErrDenied
	}
	return err
}

func (c *Client) CheckBlocked(domain string) (bool, string, error) {
	var response BlockResponse
	err := c.call(context.Background(), "block", BlockRequest{domain}, &response)
	if err != nil {
		return true, "filtering authority unavailable", err
	}
	return response.Blocked, response.Reason, nil
}
func (c *Client) IsBlocked(domain string) bool {
	blocked, _, err := c.CheckBlocked(domain)
	return blocked || err != nil
}
func (c *Client) BlockWhy(domain string) string {
	_, reason, _ := c.CheckBlocked(domain)
	return reason
}

func NewReservationID(now time.Time) (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return strconv.FormatInt(now.Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

func (c *Client) ReserveTraffic(ctx context.Context, token, generation, ingress string, down bool, n int) (access.Reservation, error) {
	id, err := NewReservationID(time.Now())
	if err != nil {
		return access.Reservation{}, err
	}
	return c.Reserve(ctx, ReserveRequest{id, token, generation, ingress, down, n})
}

// Explicit Reserve also allows a lost acknowledgement to be retried using
// exactly the same operation ID. Ordinary send paths never retry a grant after
// transmitting its bytes; a new write always gets a new operation ID.
func (c *Client) Reserve(ctx context.Context, req ReserveRequest) (access.Reservation, error) {
	var r access.Reservation
	err := c.call(ctx, "reserve", req, &r)
	if err != nil {
		return r, err
	}
	if r.ID != req.ID || r.Bytes < 1 || r.Bytes > req.Requested || len(r.Day) != 10 || r.ReadyAt < 0 || r.DelayNs < 0 || r.DelayNs > int64(5*time.Second) {
		return access.Reservation{}, ErrDenied
	}
	if _, err := time.Parse("2006-01-02", r.Day); err != nil {
		return access.Reservation{}, ErrDenied
	}
	if wait := time.Duration(r.DelayNs); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			_ = c.RefundTraffic(context.WithoutCancel(ctx), req.Token, req.Generation, req.Ingress, req.Down, r, r.Bytes)
			return access.Reservation{}, ctx.Err()
		case <-timer.C:
		}
	}
	return r, nil
}

func (c *Client) RefundTraffic(ctx context.Context, token, generation, ingress string, down bool, reservation access.Reservation, n int) error {
	var response OK
	err := c.call(ctx, "settle", Settlement{reservation.ID, token, generation, ingress, down, n}, &response)
	if err == nil && !response.OK {
		err = ErrDenied
	}
	return err
}

func (c *Client) ControlBound(ctx context.Context, req ControlRequest) (protocol.CtrlResponse, error) {
	var resp protocol.CtrlResponse
	err := c.call(ctx, "control", req, &resp)
	return resp, err
}
func (c *Client) ControlSession(ctx context.Context, req ControlRequest, channelBound bool) (protocol.CtrlResponse, error) {
	if !channelBound {
		return protocol.CtrlResponse{}, ErrDenied
	}
	return c.ControlBound(ctx, req)
}
func (c *Client) SetPeerIPBound(ctx context.Context, req PeerIPRequest) error {
	var response OK
	err := c.call(ctx, "peer-ip", req, &response)
	if err == nil && !response.OK {
		return ErrDenied
	}
	return err
}
func (c *Client) RecordVisitBound(ctx context.Context, req VisitRequest) error {
	var response OK
	err := c.call(ctx, "visit", req, &response)
	if err == nil && !response.OK {
		return ErrDenied
	}
	return err
}
func (c *Client) RecordRelayMetrics(snapshot metrics.Snapshot) error {
	var response OK
	return c.call(context.Background(), "metrics", snapshot, &response)
}
func (c *Client) RecordAlert(severity, kind, detail string) {
	var response OK
	_ = c.call(context.Background(), "event", EventRequest{severity, kind, detail}, &response)
}
func (c *Client) RecordAlertOnce(severity, kind, detail string) {
	c.RecordAlert(severity, kind, detail)
}
func (c *Client) RecordEvent(kind, detail string) {
	var response OK
	_ = c.call(context.Background(), "event", EventRequest{"", kind, detail}, &response)
}
func (c *Client) Setting(key string) string {
	var response SettingResponse
	if c.call(context.Background(), "setting", SettingRequest{key}, &response) != nil {
		return "respond"
	}
	return response.Value
}

// These legacy interface shims never mutate control state without a bound
// identity. The relay discovers and uses ControlBound/SetPeerIPBound instead.
// Quotas use ReserveTraffic and never fall back to end-of-transfer reporting.
func (c *Client) RecordTraffic(string, int64, int64) {}
func (c *Client) SetPeerIP(string, string)           {}
func (c *Client) RecordHealth(string, string, string, string, float64, float64, float64, int64, float64, float64, float64) {
}
func (c *Client) TouchPeer(string)           {}
func (c *Client) RecordVisit(string, string) {}
func (c *Client) BanReason(token string) string {
	p, err := c.AccessPolicy(token)
	if err != nil {
		return "authority unavailable"
	}
	return p.Reason
}
func (c *Client) KillSwitch() bool            { return true } // token-specific AccessPolicy is mandatory
func (c *Client) KillSwitchReason() string    { return "authoritative per-device policy required" }
func (c *Client) KillSwitchAllow(string) bool { return false }
func (c *Client) PeerLimits(token string) (int64, int64) {
	p, err := c.AccessPolicy(token)
	if err != nil {
		return 1, 1
	}
	return p.MaxBps, p.QuotaBytes
}
func (c *Client) SSHTierLimits() (int64, int64, int64) { return 1, 1, 1 } // no unbound policy bypass

func (c *Client) ForwardPublic(w http.ResponseWriter, r *http.Request, clientIP string) {
	if !publicTokenPath(r.URL.Path) || r.URL.RawPath != "" || len(clientIP) > 128 || net.ParseIP(clientIP) == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var body []byte
	var err error
	if r.Body != nil {
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	}
	defer clear(body)
	if err != nil {
		http.Error(w, "invalid token request", 400)
		return
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, c.opt.URL+r.URL.EscapedPath()+func() string {
		if r.URL.RawQuery != "" {
			return "?" + r.URL.RawQuery
		}
		return ""
	}(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "authority unavailable", 503)
		return
	}
	c.stamp(req)
	for _, key := range []string{"Content-Type", "X-Otu-Time", "X-Otu-Nonce", "X-Otu-Proof", "X-Otu-Profile-Version"} {
		if value := r.Header.Get(key); value != "" {
			req.Header.Set(key, value)
		}
	}
	req.Header.Set("X-Otu-Client-IP", clientIP)
	resp, err := c.http.Do(req)
	if err != nil {
		http.Error(w, "approval authority unavailable; no fallback", 503)
		return
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil || len(raw) > MaxResponse {
		http.Error(w, "authority response unavailable", 503)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if value := resp.Header.Get("Content-Type"); value != "" {
		w.Header().Set("Content-Type", value)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(raw)
}
