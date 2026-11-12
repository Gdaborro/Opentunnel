// Package streamio implements cancellation-aware, half-close-correct stream
// relaying. It is shared by local proxies and the relay so EOF semantics do
// not depend on which carrier was selected.
package streamio

import (
	"context"
	"errors"
	"io"
)

// Pipe relays a -> b and b -> a, propagating a clean EOF to the destination's
// write half. Errors and cancellation close BOTH endpoints and join BOTH copy
// workers. Endpoints without half-close support are closed instead of leaving
// an upload waiting forever for an EOF the peer can never receive.
func Pipe(ctx context.Context, a, b io.ReadWriteCloser) (up, down int64, err error) {
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	defer closeBoth()
	type result struct {
		n   int64
		err error
		up  bool
	}
	done := make(chan result, 2)
	copyOne := func(dst, src io.ReadWriteCloser, upstream bool) {
		n, err := io.CopyBuffer(dst, src, make([]byte, 32<<10))
		if err != nil {
			closeBoth()
		} else if cw, ok := dst.(interface{ CloseWrite() error }); !ok {
			_ = dst.Close()
		} else if err := cw.CloseWrite(); err != nil {
			_ = dst.Close()
		}
		done <- result{n: n, err: err, up: upstream}
	}
	go copyOne(b, a, true)
	go copyOne(a, b, false)
	for range 2 {
		r := <-done
		if r.up {
			up = r.n
		} else {
			down = r.n
		}
		err = errors.Join(err, r.err)
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return
}
