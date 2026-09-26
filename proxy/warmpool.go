/*-
 * Copyright 2026 Ghostunnel contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// The warm backend pool keeps up to WarmBackendConnections connections to
// the backend dialed ahead of any client, so that a served connection takes
// one instead of dialing on its own path. It is off unless the operator
// sets a size, and with it off nothing here runs.
//
// What changes for the backend: it sees connections opened before a client
// exists, each idle until a client is served on it or until it is closed
// unused (after WarmBackendIdle, on CloseAll, on Shutdown, or because the
// backend ended it). What does not change: every byte the backend receives
// on a connection is written by a handler for one accepted client, in the
// same order as without the pool (the PROXY protocol header, if configured,
// first); a TLS backend connection is handshaken at dial time, before it is
// pooled, exactly as a dial on the handler's path is; the dial function,
// its timeout and the target are the proxy's own. What the client and the
// observer see is unchanged: the observer's Dialed callback reports the
// backend connection the client was served on, pooled or not.
//
// A pooled connection is handed out only if a probe shows it still open. A
// reader goroutine waits in Read on every pooled connection (nothing is
// expected on it, so the read only ever ends with the backend closing or
// erroring, or with the handout's deadline): the backend closing the
// connection is seen at once and the connection is closed and replaced.
// The handout sets a read deadline in the past, which ends the pending
// Read: a timeout means the socket was still open, anything else means it
// was not and the next pooled connection is tried. A backend that sends
// before the client does cannot be pooled, because the bytes it sends
// before a client exists belong to no client: such a connection is closed
// and the pool reports why, and every connection is served by its own dial.

// DefaultWarmBackendIdle is how long a pooled backend connection may stay
// idle before it is closed and replaced, when WarmBackendIdle is zero.
const DefaultWarmBackendIdle = 30 * time.Second

// warmDialKey marks the context of a dial made to fill the pool.
type warmDialKey struct{}

// DialedForWarmPool reports whether the dial with this context is made to
// fill the warm backend pool, rather than by a handler for a connection it
// has accepted. A DialFunc may use it to tell the two apart, for logging.
func DialedForWarmPool(ctx context.Context) bool {
	warm, _ := ctx.Value(warmDialKey{}).(bool)
	return warm
}

// errBackendSpokeFirst is the pool's reason for closing a connection the
// backend wrote on before any client was served on it.
var errBackendSpokeFirst = errors.New("the backend sent data on an idle pooled connection before any client was served on it; the warm backend pool cannot be used with a backend that speaks first")

// warmConn is one pooled connection: when it was pooled, and the outcome
// of the reader waiting on it, sent exactly once.
type warmConn struct {
	conn   net.Conn
	pooled time.Time
	// taken is set, under the pool's lock, once the connection has left the
	// pool's list (handed out, expired or drained), so that the reader does
	// not close it too.
	taken bool
	// result carries the reader's outcome: nil for a timeout (the handout's
	// probe found the socket open), else why the connection is dead.
	result chan error
}

// warmPool is the pool of pre-dialed backend connections.
type warmPool struct {
	p    *Proxy
	size int
	idle time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex
	// conns is the pooled connections, oldest first.
	conns []*warmConn
	// dialing is how many dials are in flight to fill the pool.
	dialing int
	// paused is set by a drain that is not for good: the pool stays empty
	// until a connection is served again, and fills then.
	paused bool
	// closed is set by a drain for good: nothing is dialed again.
	closed bool
	// backoff and retryAt delay the next dial after a failed one, from
	// acceptBackoffMin doubling to acceptBackoffMax, reset by a success.
	backoff time.Duration
	retryAt time.Time

	// wake asks the manager to look at the pool again.
	wake chan struct{}
}

func newWarmPool(p *Proxy, size int, idle time.Duration) *warmPool {
	ctx, cancel := context.WithCancel(p.context)
	w := &warmPool{
		p:      p,
		size:   size,
		idle:   idle,
		ctx:    ctx,
		cancel: cancel,
		wake:   make(chan struct{}, 1),
	}
	go w.run()
	return w
}

// signal wakes the manager; a wake already pending is enough.
func (w *warmPool) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// run is the manager: it keeps the pool full, expires idle connections
// and waits out the backoff after a failed dial, until the pool is closed.
func (w *warmPool) run() {
	sweep := time.NewTicker(max(w.idle/2, time.Millisecond))
	defer sweep.Stop()
	for {
		w.fill()

		var retry <-chan time.Time
		w.mu.Lock()
		if !w.retryAt.IsZero() {
			retry = time.After(max(time.Until(w.retryAt), 0))
		}
		w.mu.Unlock()

		select {
		case <-w.ctx.Done():
			return
		case <-w.wake:
		case <-sweep.C:
			w.expire()
		case <-retry:
			w.mu.Lock()
			w.retryAt = time.Time{}
			w.mu.Unlock()
		}
	}
}

// fill starts a dial for every empty slot, unless the pool is paused,
// closed or waiting out a backoff.
func (w *warmPool) fill() {
	w.mu.Lock()
	if w.closed || w.paused || !w.retryAt.IsZero() {
		w.mu.Unlock()
		return
	}
	n := w.size - len(w.conns) - w.dialing
	if n > 0 {
		w.dialing += n
	}
	w.mu.Unlock()
	for i := 0; i < n; i++ {
		go w.dial()
	}
}

// dial fills one slot: the proxy's own dial with its own timeout, marked
// as the pool's, then the connection is pooled and its reader started. A
// connection the pool cannot take (drained meanwhile) is closed at once.
func (w *warmPool) dial() {
	ctx, cancel := context.WithTimeout(context.WithValue(w.ctx, warmDialKey{}, true), w.p.ConnectTimeout)
	defer cancel()
	conn, err := w.p.Dial(ctx)

	w.mu.Lock()
	w.dialing--
	if err != nil {
		backoff := w.backOffLocked()
		w.mu.Unlock()
		if w.ctx.Err() == nil {
			w.p.logConditional(LogConnectionErrors, "warm backend pool: error on dial: %s (next attempt in %s)", err, backoff)
		}
		w.signal()
		return
	}
	if w.closed || w.paused || len(w.conns) >= w.size {
		w.mu.Unlock()
		_ = conn.Close()
		return
	}
	// A dial that succeeds is not yet evidence the backend tolerates
	// pooling (it may speak first, or close at once): the backoff is reset
	// once a pooled connection is handed out alive or idles to expiry.
	w.p.setSocketBuffers(conn)
	wc := &warmConn{conn: conn, pooled: time.Now(), result: make(chan error, 1)}
	w.conns = append(w.conns, wc)
	w.mu.Unlock()
	// This goroutine goes on as the connection's reader: one goroutine per
	// pooled connection, not two.
	w.read(wc)
}

// backOffLocked delays the next fill after a failed one (a dial error, or
// a backend that spoke first, which would otherwise be redialed in a hot
// loop), from acceptBackoffMin doubling to acceptBackoffMax. Called with
// the lock held; returns the delay.
func (w *warmPool) backOffLocked() time.Duration {
	if w.backoff == 0 {
		w.backoff = acceptBackoffMin
	} else {
		w.backoff = min(w.backoff*2, acceptBackoffMax)
	}
	w.retryAt = time.Now().Add(w.backoff)
	return w.backoff
}

// read waits on a pooled connection until the backend ends it (or writes
// on it), or until a handout's deadline ends the wait, and reports which.
func (w *warmPool) read(wc *warmConn) {
	var b [1]byte
	n, err := wc.conn.Read(b[:])
	if err == nil {
		if n == 0 {
			// Nothing read and no error: not a socket, or a stub that
			// returns nothing. It cannot be probed, so it is not pooled.
			err = errors.New("the pooled connection returned no data and no error from Read")
		} else {
			err = errBackendSpokeFirst
		}
	}

	w.mu.Lock()
	if isTimeoutError(err) && wc.taken {
		// The handout's probe: the socket was still open.
		w.mu.Unlock()
		wc.result <- nil
		return
	}
	// Dead, or ended by a drain or expiry (already taken): the handout,
	// if one is waiting, is told; if still pooled it is removed here. A
	// backend that spoke first would speak first on the replacement too,
	// so the replacement waits out a backoff.
	removed := w.remove(wc)
	var backoff time.Duration
	if removed && errors.Is(err, errBackendSpokeFirst) {
		backoff = w.backOffLocked()
	}
	w.mu.Unlock()
	wc.result <- err
	if removed {
		_ = wc.conn.Close()
		if w.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			if backoff > 0 {
				w.p.logConditional(LogConnectionErrors, "warm backend pool: pooled connection to %s closed: %s (next attempt in %s)", wc.conn.RemoteAddr(), err, backoff)
			} else {
				w.p.logConditional(LogConnectionErrors, "warm backend pool: pooled connection to %s closed: %s", wc.conn.RemoteAddr(), err)
			}
		}
		w.signal()
	}
}

// remove takes wc out of the pooled list if it is still there, under the
// lock, and reports whether it was.
func (w *warmPool) remove(wc *warmConn) bool {
	if wc.taken {
		return false
	}
	wc.taken = true
	for i, c := range w.conns {
		if c == wc {
			copy(w.conns[i:], w.conns[i+1:])
			w.conns[len(w.conns)-1] = nil
			w.conns = w.conns[:len(w.conns)-1]
			return true
		}
	}
	return false
}

// take hands out the oldest pooled connection that is not idle for too
// long and whose probe finds it open, or nil if there is none (the caller
// dials itself). Taking from a paused pool resumes it: a connection is
// being served again, so the pool fills again in the background.
func (w *warmPool) take() net.Conn {
	for {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return nil
		}
		if w.paused {
			w.paused = false
			w.mu.Unlock()
			w.signal()
			return nil
		}
		if len(w.conns) == 0 {
			w.mu.Unlock()
			w.signal()
			return nil
		}
		wc := w.conns[0]
		w.conns[0] = nil
		w.conns = w.conns[1:]
		wc.taken = true
		expired := time.Since(wc.pooled) >= w.idle
		w.mu.Unlock()
		w.signal()

		if expired {
			_ = wc.conn.Close()
			continue
		}
		// The probe: end the reader's pending Read with a deadline in the
		// past. A timeout means the socket was open; anything else, that
		// the backend had ended it.
		if err := wc.conn.SetReadDeadline(time.Unix(1, 0)); err != nil {
			_ = wc.conn.Close()
			continue
		}
		if err := <-wc.result; err != nil {
			_ = wc.conn.Close()
			continue
		}
		if err := wc.conn.SetReadDeadline(time.Time{}); err != nil {
			_ = wc.conn.Close()
			continue
		}
		w.resetBackoff()
		return wc.conn
	}
}

// resetBackoff forgets the delay after failures: a pooled connection has
// proved usable (handed out alive, or idle to expiry untouched).
func (w *warmPool) resetBackoff() {
	w.mu.Lock()
	w.backoff = 0
	w.mu.Unlock()
}

// expire closes every pooled connection idle for the limit or longer; the
// manager refills.
func (w *warmPool) expire() {
	w.mu.Lock()
	var expired []*warmConn
	kept := w.conns[:0]
	for _, wc := range w.conns {
		if time.Since(wc.pooled) >= w.idle {
			wc.taken = true
			expired = append(expired, wc)
		} else {
			kept = append(kept, wc)
		}
	}
	for i := len(kept); i < len(w.conns); i++ {
		w.conns[i] = nil
	}
	w.conns = kept
	if len(expired) > 0 {
		w.backoff = 0
	}
	w.mu.Unlock()
	for _, wc := range expired {
		_ = wc.conn.Close()
	}
}

// drain closes every pooled connection. For good (Shutdown), nothing is
// dialed again and a dial in flight is abandoned, its connection closed if
// it completes. Otherwise (CloseAll) the pool pauses: empty until a
// connection is served again.
func (w *warmPool) drain(forGood bool) {
	w.mu.Lock()
	conns := w.conns
	w.conns = nil
	for _, wc := range conns {
		wc.taken = true
	}
	if forGood {
		w.closed = true
	} else {
		w.paused = true
	}
	w.mu.Unlock()
	for _, wc := range conns {
		_ = wc.conn.Close()
	}
	if forGood {
		w.cancel()
	}
}
