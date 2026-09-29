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
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// echoBackend is a plain TCP backend that echoes every connection until the
// client half-closes, and keeps every connection it accepted so a test can
// end one from the backend's side or watch it end.
type echoBackend struct {
	ln       net.Listener
	mu       sync.Mutex
	accepted []net.Conn
	// eof receives every accepted connection once the backend has read EOF
	// (or an error) on it, i.e. once the proxy's side is closed.
	eof chan net.Conn
}

func newEchoBackend(t *testing.T) *echoBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &echoBackend{ln: ln, eof: make(chan net.Conn, 1024)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.accepted = append(e.accepted, c)
			e.mu.Unlock()
			go func() {
				// Echo until the far side finishes or errors, then report it.
				_, _ = io.Copy(c, c)
				e.eof <- c
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return e
}

// count is how many connections the backend has accepted so far.
func (e *echoBackend) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.accepted)
}

// conn is the i-th accepted connection (backend side).
func (e *echoBackend) conn(i int) net.Conn {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.accepted[i]
}

// awaitAccepted waits until the backend has accepted at least n connections.
func (e *echoBackend) awaitAccepted(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("backend accepted %d connections, waiting for %d", e.count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// awaitEOF waits until the backend has seen n of its connections end.
func (e *echoBackend) awaitEOF(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-e.eof:
		case <-time.After(5 * time.Second):
			t.Fatalf("backend saw %d of %d connections end", i, n)
		}
	}
}

// countingDialer dials the backend and counts dials made for the warm pool
// separately from dials made by a handler for an accepted connection: the
// seam that proves a served connection performed no dial on its own path.
type countingDialer struct {
	addr    string
	pool    atomic.Int64
	handler atomic.Int64
}

func (d *countingDialer) dial(ctx context.Context) (net.Conn, error) {
	if DialedForWarmPool(ctx) {
		d.pool.Add(1)
	} else {
		d.handler.Add(1)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.addr)
}

// warmProxyForTest is a proxy in front of the echo backend with a warm pool
// of the given size and idle limit, its accept loop running.
func warmProxyForTest(t *testing.T, e *echoBackend, warm int, idle time.Duration) (*Proxy, *countingDialer, net.Listener) {
	t.Helper()
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &countingDialer{addr: e.ln.Addr().String()}
	p := New(incoming, 5*time.Second, 5*time.Second, 0, 0, d.dial, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
	p.WarmBackendConnections = warm
	p.WarmBackendIdle = idle
	go p.Accept()
	t.Cleanup(func() {
		p.Shutdown()
		p.Wait()
	})
	return p, d, incoming
}

// echoThrough opens a client connection through the proxy, sends one byte
// and expects it back.
func echoThrough(t *testing.T, incoming net.Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", incoming.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Closed at cleanup, before the proxy's Shutdown and Wait (cleanups run
	// last registered first): Wait waits for every served connection, and
	// a test that fails mid-way must not leave one open.
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		t.Fatalf("no echo through the proxy: %v", err)
	}
	if b[0] != 'A' {
		t.Fatalf("echoed %q, want A", b[:])
	}
	return c
}

// TestWarmPoolServesWithoutDialOnCriticalPath: with a pool of four, the
// first four served connections perform no dial of their own, and the pool
// refills in the background to four again.
func TestWarmPoolServesWithoutDialOnCriticalPath(t *testing.T) {
	e := newEchoBackend(t)
	_, d, incoming := warmProxyForTest(t, e, 4, time.Minute)

	e.awaitAccepted(t, 4)
	if got := d.pool.Load(); got != 4 {
		t.Fatalf("pool dialed %d, want 4", got)
	}
	if got := d.handler.Load(); got != 0 {
		t.Fatalf("no handler has run yet, but %d handler dials", got)
	}

	var clients []net.Conn
	for i := 0; i < 4; i++ {
		clients = append(clients, echoThrough(t, incoming))
	}
	if got := d.handler.Load(); got != 0 {
		t.Fatalf("the first four connections must be served from the pool: %d handler dials", got)
	}

	// The pool refills to four in the background: four more pool dials.
	e.awaitAccepted(t, 8)
	if got := d.pool.Load(); got != 8 {
		t.Fatalf("pool dialed %d, want 8 after refill", got)
	}
	for _, c := range clients {
		_ = c.Close()
	}
}

// TestWarmPoolSkipsDeadConnection: a pooled connection the backend has
// closed is never handed out; the next connection is served on a live one
// and the dead one is replaced.
func TestWarmPoolSkipsDeadConnection(t *testing.T) {
	e := newEchoBackend(t)
	_, d, incoming := warmProxyForTest(t, e, 2, time.Minute)
	e.awaitAccepted(t, 2)

	// The backend ends the first pooled connection (the one handed out
	// first, the pool being first in, first out).
	_ = e.conn(0).Close()

	c := echoThrough(t, incoming)
	defer c.Close()
	if got := d.handler.Load(); got != 0 {
		t.Fatalf("served on a pooled connection, want no handler dial: %d", got)
	}
	// The dead one is replaced, and the one handed out is replaced.
	e.awaitAccepted(t, 4)
	if got := d.pool.Load(); got != 4 {
		t.Fatalf("pool dialed %d, want 4", got)
	}
}

// TestWarmPoolIdleExpiry: a pooled connection idle longer than the limit
// is closed and replaced without any client.
func TestWarmPoolIdleExpiry(t *testing.T) {
	e := newEchoBackend(t)
	_, d, _ := warmProxyForTest(t, e, 2, 100*time.Millisecond)
	e.awaitAccepted(t, 2)
	// Both expire and are replaced: the backend sees two ends and two more
	// accepts.
	e.awaitEOF(t, 2)
	e.awaitAccepted(t, 4)
	if got := d.handler.Load(); got != 0 {
		t.Fatalf("no handler ran, but %d handler dials", got)
	}
}

// TestWarmPoolDrainedByCloseAll: CloseAll closes every pooled connection
// and the pool does not refill until a connection is served again; that
// connection dials for itself, and the pool then refills.
func TestWarmPoolDrainedByCloseAll(t *testing.T) {
	e := newEchoBackend(t)
	p, d, incoming := warmProxyForTest(t, e, 3, time.Minute)
	e.awaitAccepted(t, 3)

	if got := p.CloseAll(CloseHalt); got != 0 {
		t.Fatalf("CloseAll closed %d live connections, want 0: pooled connections are not accepted ones", got)
	}
	e.awaitEOF(t, 3)
	time.Sleep(300 * time.Millisecond)
	if got := e.count(); got != 3 {
		t.Fatalf("the pool refilled while drained: backend accepted %d, want 3", got)
	}

	c := echoThrough(t, incoming)
	defer c.Close()
	if got := d.handler.Load(); got != 1 {
		t.Fatalf("the first connection after a drain dials for itself: %d handler dials", got)
	}
	// Serving resumed: the pool fills again.
	e.awaitAccepted(t, 3+1+3)
}

// TestWarmPoolDrainedByShutdown: Shutdown closes every pooled connection and
// nothing is dialed afterwards.
func TestWarmPoolDrainedByShutdown(t *testing.T) {
	e := newEchoBackend(t)
	p, d, _ := warmProxyForTest(t, e, 3, time.Minute)
	e.awaitAccepted(t, 3)

	p.Shutdown()
	p.Wait()
	e.awaitEOF(t, 3)
	time.Sleep(200 * time.Millisecond)
	if got := e.count(); got != 3 {
		t.Fatalf("dialed after shutdown: backend accepted %d, want 3", got)
	}
	if got := d.pool.Load(); got != 3 {
		t.Fatalf("pool dialed %d, want 3", got)
	}
}

// TestWarmPoolDialErrorBacksOff: a backend that cannot be dialed is retried
// with backoff, not in a hot loop, and the proxy still serves (the handler
// reports the dial error as it does without a pool).
func TestWarmPoolDialErrorBacksOff(t *testing.T) {
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	dialer := func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("failure for test")
	}
	p := New(incoming, 5*time.Second, 5*time.Second, 0, 0, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
	p.WarmBackendConnections = 4
	// The observer is installed before the accept loop starts: it is read
	// by that loop, and a write after it runs is a race.
	obs := newRecordingObserver()
	p.Observer = obs
	go p.Accept()
	defer func() {
		p.Shutdown()
		p.Wait()
	}()
	time.Sleep(300 * time.Millisecond)
	// Backoff starts at 5ms and doubles to 1s: four dials at once, then
	// one retry per backoff step (5, 10, 20, 40, 80, 160 ms), so a handful.
	if got := dials.Load(); got > 40 {
		t.Fatalf("%d dials in 300ms: the pool retries without backoff", got)
	}
	c, err := net.Dial("tcp", incoming.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := obs.awaitClose(t); got != CloseError {
		t.Fatalf("a connection whose backend cannot be dialed ends with %s, want error", got)
	}
}

// TestWarmPoolBackendSpeaksFirst: a backend that sends before the client
// does cannot be pooled: a pooled connection it has written on is closed
// and never handed out (so no byte of the backend's is lost: the client
// receives the greeting whole, whether served on a pooled connection the
// greeting had not reached yet or by its own dial), the pool backs off
// instead of redialing such a backend in a hot loop, and the proxy serves.
func TestWarmPoolBackendSpeaksFirst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				_, _ = c.Write([]byte("HELLO\n"))
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &countingDialer{addr: ln.Addr().String()}
	p := New(incoming, 5*time.Second, 5*time.Second, 0, 0, d.dial, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
	p.WarmBackendConnections = 2
	go p.Accept()
	defer func() {
		p.Shutdown()
		p.Wait()
	}()
	time.Sleep(300 * time.Millisecond)
	// Two dials at once, then one retry per backoff step (5, 10, 20, 40,
	// 80, 160 ms): a handful, not a hot loop.
	if got := accepted.Load(); got > 40 {
		t.Fatalf("%d connections to a backend that speaks first in 300ms: the pool redials it without backoff", got)
	}

	c, err := net.Dial("tcp", incoming.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// The greeting arrives whole: nothing of it was consumed by the pool.
	got := make([]byte, 6)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "HELLO\n" {
		t.Fatalf("greeting %q, want HELLO", got)
	}
	if d.handler.Load() > 1 {
		t.Fatalf("one connection served, %d handler dials", d.handler.Load())
	}
}

// awaitPooled waits until the proxy's pool has started and holds at least
// n connections, and returns the pool.
func awaitPooled(t *testing.T, p *Proxy, n int) *warmPool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	w := p.warmPool()
	for w == nil {
		if time.Now().After(deadline) {
			t.Fatal("the warm pool never started")
		}
		time.Sleep(5 * time.Millisecond)
		w = p.warmPool()
	}
	for {
		w.mu.Lock()
		got := len(w.conns)
		w.mu.Unlock()
		if got >= n {
			return w
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool holds %d connections, waiting for %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestWarmPoolHandoutForgetsBackoff: a pooled connection handed out alive
// has proved the backend usable, so the delay after failures is forgotten;
// the connection comes back with no deadline left on it.
func TestWarmPoolHandoutForgetsBackoff(t *testing.T) {
	e := newEchoBackend(t)
	p, _, _ := warmProxyForTest(t, e, 1, time.Minute)
	w := awaitPooled(t, p, 1)
	w.mu.Lock()
	w.backoff = acceptBackoffMax
	w.mu.Unlock()

	c := w.take()
	if c == nil {
		t.Fatal("a live pooled connection was not handed out")
	}
	defer c.Close()
	w.mu.Lock()
	got := w.backoff
	w.mu.Unlock()
	if got != 0 {
		t.Fatalf("backoff %s after a live handout, want 0", got)
	}
	// No deadline is left: a read waits for the backend's echo.
	if _, err := c.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := c.Read(b[:]); err != nil {
		t.Fatalf("the handed-out connection kept a deadline: %v", err)
	}
}

// stuckDeadlineConn refuses to clear its read deadline.
type stuckDeadlineConn struct {
	net.Conn
}

func (c stuckDeadlineConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		return errors.New("deadline cannot be cleared, for test")
	}
	return c.Conn.SetReadDeadline(t)
}

// TestWarmPoolHandoutKeepsBackoffWhenTheDeadlineStays: a pooled connection
// whose probe deadline cannot be cleared is not handed out (it is closed,
// and the handler dials itself), and it has proved nothing, so the delay
// after failures stands.
func TestWarmPoolHandoutKeepsBackoffWhenTheDeadlineStays(t *testing.T) {
	e := newEchoBackend(t)
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dialer := func(ctx context.Context) (net.Conn, error) {
		var nd net.Dialer
		c, err := nd.DialContext(ctx, "tcp", e.ln.Addr().String())
		if err != nil {
			return nil, err
		}
		return stuckDeadlineConn{c}, nil
	}
	p := New(incoming, 5*time.Second, 5*time.Second, 0, 0, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
	p.WarmBackendConnections = 1
	p.WarmBackendIdle = time.Minute
	go p.Accept()
	t.Cleanup(func() {
		p.Shutdown()
		p.Wait()
	})
	w := awaitPooled(t, p, 1)
	w.mu.Lock()
	w.backoff = acceptBackoffMax
	w.mu.Unlock()

	if c := w.take(); c != nil {
		c.Close()
		t.Fatal("a connection whose deadline could not be cleared was handed out")
	}
	w.mu.Lock()
	got := w.backoff
	w.mu.Unlock()
	if got != acceptBackoffMax {
		t.Fatalf("backoff %s after a failed handout, want %s", got, acceptBackoffMax)
	}
}
