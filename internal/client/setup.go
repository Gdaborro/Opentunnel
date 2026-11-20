package client

import (
	"context"
	"errors"
	"net"
	"time"

	"opentunnel/internal/transport"
)

func (c *Client) setupBudget() time.Duration {
	if c.opts.DialTimeout <= 0 {
		return 15 * time.Second
	}
	return c.opts.DialTimeout
}

// beginSetup bounds the entire establishment operation. Its private owner
// context is canceled on drain/close, but never owns an established stream.
func (c *Client) beginSetup(parent context.Context, budget time.Duration) (context.Context, func(), error) {
	if c.setupError != nil {
		return nil, nil, c.setupError
	}
	c.lifecycleMu.Lock()
	if c.closed || c.draining {
		c.lifecycleMu.Unlock()
		return nil, nil, net.ErrClosed
	}
	if c.setupCtx == nil {
		c.setupCtx, c.cancelSetups = context.WithCancel(context.Background())
	}
	owner := c.setupCtx
	c.lifecycleMu.Unlock()
	setup, cancel := context.WithTimeout(parent, budget)
	stop := context.AfterFunc(owner, cancel)
	return setup, func() { stop(); cancel() }, nil
}

// bindSetupIO closes only this stream on cancellation. Stopping the callback
// and clearing the deadline is an explicit success boundary, not a timer reset
// between transport, authentication and target phases.
func bindSetupIO(ctx context.Context, conn net.Conn) (func() error, error) {
	if err := ctx.Err(); err != nil {
		transport.AbortSetup(conn)
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("client: setup requires a bounded deadline")
	}
	if err := conn.SetDeadline(deadline); err != nil {
		transport.AbortSetup(conn)
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { transport.AbortSetup(conn) })
	return func() error {
		if !stop() || ctx.Err() != nil {
			transport.AbortSetup(conn)
			if err := ctx.Err(); err != nil {
				return err
			}
			return context.Canceled
		}
		return conn.SetDeadline(time.Time{})
	}, nil
}

// dialSetupCarrier keeps legacy transports cancellable during setup without
// assigning the setup timeout to their successful connection's lifetime.
func dialSetupCarrier(tr transport.Transport, setup, lifetime context.Context) (net.Conn, context.CancelFunc, error) {
	carrierLife, cancelLife := context.WithCancel(lifetime)
	stop := context.AfterFunc(setup, cancelLife)
	var conn net.Conn
	var err error
	if dialer, ok := tr.(transport.SetupDialer); ok {
		conn, err = dialer.DialSetup(setup, carrierLife)
	} else {
		conn, err = tr.Dial(carrierLife)
	}
	stopped := stop()
	if err != nil || !stopped || setup.Err() != nil || lifetime.Err() != nil || conn == nil {
		cancelLife()
		transport.AbortSetup(conn)
		if setup.Err() != nil {
			return nil, nil, setup.Err()
		}
		if lifetime.Err() != nil {
			return nil, nil, lifetime.Err()
		}
		if err == nil {
			err = context.Canceled
		}
		return nil, nil, err
	}
	return conn, cancelLife, nil
}
