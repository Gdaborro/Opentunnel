package client

import (
	"context"
	"errors"
	"net"
	"testing"
)

type contextCloseConn struct {
	net.Conn
	ctx              context.Context
	closedWhileAlive bool
}

func (c *contextCloseConn) Close() error {
	c.closedWhileAlive = c.ctx.Err() == nil
	if !c.closedWhileAlive {
		return errors.New("carrier close context was canceled too early")
	}
	return c.Conn.Close()
}
func TestCarrierClosePrecedesSessionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	a, b := net.Pipe()
	defer b.Close()
	carrier := &contextCloseConn{Conn: a, ctx: ctx}
	conn := &countingConn{Conn: carrier, cancel: cancel}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !carrier.closedWhileAlive || ctx.Err() == nil {
		t.Fatal("close/cancel lifetime ordering changed")
	}
}
