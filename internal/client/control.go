// control.go: client end of the in-band control channel (v0.9.23). Status
// polls and health telemetry ride a dedicated stream inside the
// authenticated mux session; pinned HTTPS remains the fallback for
// tunnel-less bootstrap. On TLS-intercepting networks (where pinned HTTPS
// refuses the MITM cert BY DESIGN) this is the path that keeps the panel
// informed — invisible to the middlebox, no extra flows.
package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"opentunnel/internal/protocol"
)

// ctrlTimeout bounds one in-band exchange.
const ctrlTimeout = 20 * time.Second

// DialControl opens a control stream on the client's mux pool: one smux
// stream whose first byte marks it as a control channel.
func (c *Client) DialControl(ctx context.Context) (net.Conn, error) {
	if !c.opts.Mux {
		return nil, errors.New("client: control channel requires mux")
	}
	stream, err := c.getPool().Open(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := stream.Write([]byte{protocol.CtrlMarker}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

// CtrlExchange sends one control request and reads the response.
func (c *Client) CtrlExchange(ctx context.Context, req protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
	conn, err := c.DialControl(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ctrlTimeout))
	if err := protocol.WriteCtrlMessage(conn, req); err != nil {
		return nil, err
	}
	var resp protocol.CtrlResponse
	if err := protocol.ReadCtrlMessage(conn, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ctrlFn holds the installed in-band exchange (nil = HTTPS only).
var (
	ctrlMu sync.Mutex
	ctrlFn func(context.Context, protocol.CtrlRequest) (*protocol.CtrlResponse, error)
)

// SetControlChannel installs the tunnel-riding control exchange consulted
// by the status poll and health reporter before their pinned-HTTPS
// fallbacks. nil uninstalls (tests, shutdown).
func SetControlChannel(fn func(context.Context, protocol.CtrlRequest) (*protocol.CtrlResponse, error)) {
	ctrlMu.Lock()
	ctrlFn = fn
	ctrlMu.Unlock()
}

// currentCtrl returns the installed exchange or nil.
func currentCtrl() func(context.Context, protocol.CtrlRequest) (*protocol.CtrlResponse, error) {
	ctrlMu.Lock()
	defer ctrlMu.Unlock()
	return ctrlFn
}
