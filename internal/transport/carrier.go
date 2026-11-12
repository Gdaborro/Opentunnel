package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/proxy"

	"opentunnel/internal/netutil"
)

// CarrierOptions adapts an EXTERNALLY managed authenticated transport to v5,
// AEAD and mux. This is not a REALITY implementation and cannot attest what
// the operator's companion uses. Both ends must be explicit loopback endpoints.
type CarrierOptions struct {
	SOCKSAddr, Target, Path  string
	DialTimeout              time.Duration
	SOCKSUser, SOCKSPassword string
	Ready                    func(context.Context) error
}
type carrierTransport struct{ opt CarrierOptions }

func NewCarrier(opt CarrierOptions) Transport { return &carrierTransport{opt: opt} }
func (t *carrierTransport) Name() string      { return "external-carrier" }

func NewCarrierHTTPClient(opt CarrierOptions) (*http.Client, error) {
	if err := netutil.LoopbackEndpoint(opt.SOCKSAddr); err != nil {
		return nil, fmt.Errorf("carrier SOCKS: %w", err)
	}
	if err := netutil.LoopbackEndpoint(opt.Target); err != nil {
		return nil, fmt.Errorf("carrier target: %w", err)
	}
	timeout := opt.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	var auth *proxy.Auth
	if opt.SOCKSUser != "" || opt.SOCKSPassword != "" {
		auth = &proxy.Auth{User: opt.SOCKSUser, Password: opt.SOCKSPassword}
	}
	socks, err := proxy.SOCKS5("tcp", opt.SOCKSAddr, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, err
	}
	cd, ok := socks.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("carrier SOCKS dialer does not support cancellation")
	}
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" || addr != opt.Target {
				return nil, fmt.Errorf("carrier attempted a non-fixed destination")
			}
			if opt.Ready != nil {
				if err := opt.Ready(ctx); err != nil {
					return nil, err
				}
			}
			return cd.DialContext(ctx, network, opt.Target)
		}, DisableKeepAlives: true, ResponseHeaderTimeout: timeout,
	}}, nil
}

func (t *carrierTransport) Dial(ctx context.Context) (net.Conn, error) {
	cl, err := NewCarrierHTTPClient(t.opt)
	if err != nil {
		return nil, err
	}
	defer cl.CloseIdleConnections()
	timeout := t.opt.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	path := t.opt.Path
	if path == "" {
		path = DefaultWSPath
	}
	dial := func(path string) (*websocket.Conn, *http.Response, error) {
		return websocket.Dial(dctx, "ws://"+t.opt.Target+path, &websocket.DialOptions{HTTPClient: cl, HTTPHeader: http.Header{"User-Agent": {BrowserUA}}})
	}
	c, _, err := dialWSWithLegacyFallback(dial, path)
	if err != nil {
		return nil, fmt.Errorf("external carrier: %w", err)
	}
	return &wsConn{Conn: websocket.NetConn(ctx, c, websocket.MessageBinary), wsc: c, close: func() { _ = c.Close(websocket.StatusNormalClosure, "") }}, nil
}
