package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// recordingObserver records every callback, refuses at Accepted when refuse
// is set and at Dialed when refuseDialed is set.
type recordingObserver struct {
	mu           sync.Mutex
	refuse       error
	refuseDialed error
	accepts      int
	acceptErrors []acceptFailure
	dialed       []error
	closed       []CloseReason
	done         chan struct{}
}

type acceptFailure struct {
	err     error
	backoff time.Duration
}

// capturingLogger keeps what the proxy logged, for assertions.
type capturingLogger struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *capturingLogger) Printf(format string, v ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, format+"\n", v...)
}

func (l *capturingLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (o *recordingObserver) AcceptError(err error, backoff time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.acceptErrors = append(o.acceptErrors, acceptFailure{err, backoff})
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{done: make(chan struct{}, 16)}
}

func (o *recordingObserver) Accepted(conn net.Conn) (ConnObserver, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.accepts++
	if o.refuse != nil {
		return nil, o.refuse
	}
	return o, nil
}

func (o *recordingObserver) Handshake(state *tls.ConnectionState, err error) {}

func (o *recordingObserver) Dialed(backend net.Conn, err error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dialed = append(o.dialed, err)
	return o.refuseDialed
}

func (o *recordingObserver) Closed(reason CloseReason) {
	o.mu.Lock()
	o.closed = append(o.closed, reason)
	o.mu.Unlock()
	o.done <- struct{}{}
}

func (o *recordingObserver) awaitClose(t *testing.T) CloseReason {
	t.Helper()
	select {
	case <-o.done:
	case <-time.After(10 * time.Second):
		t.Fatal("connection was never closed")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed[len(o.closed)-1]
}

func observedProxy(t *testing.T, dialer DialFunc, lifetime time.Duration, obs Observer) (*Proxy, net.Listener) {
	t.Helper()
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	p := New(incoming, 5*time.Second, 200*time.Millisecond, lifetime, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
	p.Observer = obs
	go p.Accept()
	return p, incoming
}

func TestObserverRefusesBeforeDial(t *testing.T) {
	dialed := make(chan struct{}, 1)
	dialer := func(ctx context.Context) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, errors.New("must not be reached")
	}
	obs := newRecordingObserver()
	obs.refuse = errors.New("gate: halt in force")
	p, incoming := observedProxy(t, dialer, 0, obs)
	defer p.Shutdown()

	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)
	defer src.Close()
	// The connection is closed unserved: a read sees EOF or a reset.
	_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = src.Read(make([]byte, 1))
	assert.NotNil(t, err, "a refused connection must be closed")

	p.Shutdown()
	p.Wait()
	select {
	case <-dialed:
		t.Fatal("backend must not be dialed for a refused connection")
	default:
	}
	assert.Equal(t, 1, obs.accepts)
	assert.Empty(t, obs.closed, "no Closed callback for a refused connection")
}

func TestObserverSeesServedConnection(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer target.Close()
	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}
	obs := newRecordingObserver()
	p, incoming := observedProxy(t, dialer, 0, obs)
	defer p.Shutdown()

	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)
	dst, err := target.Accept()
	assert.Nil(t, err)
	_, _ = src.Write([]byte("A"))
	buf := make([]byte, 1)
	_, err = dst.Read(buf)
	assert.Nil(t, err)
	src.Close()
	dst.Close()

	assert.Equal(t, CloseEOF, obs.awaitClose(t))
	assert.Equal(t, []error{nil}, obs.dialed)
}

func TestObserverSeesDialError(t *testing.T) {
	dialErr := errors.New("failure for test")
	dialer := func(ctx context.Context) (net.Conn, error) { return nil, dialErr }
	obs := newRecordingObserver()
	p, incoming := observedProxy(t, dialer, 0, obs)
	defer p.Shutdown()

	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)
	defer src.Close()

	assert.Equal(t, CloseError, obs.awaitClose(t))
	assert.Equal(t, []error{dialErr}, obs.dialed)
}

// TestObserverDialedRefusesBeforeForwarding: an error from Dialed closes
// both sides before any byte is forwarded. The backend sees the dial (its
// Accept returns) and then EOF with nothing read, even though the client
// wrote before the refusal; the client is closed; the observer is told
// refused, once; the proxy logs the refusal.
func TestObserverDialedRefusesBeforeForwarding(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer target.Close()
	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}
	obs := newRecordingObserver()
	obs.refuseDialed = errors.New("record not durable")
	logs := &capturingLogger{}
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	p := New(incoming, 5*time.Second, 200*time.Millisecond, 0, 1, dialer, logs, LogEverything, ProxyProtocolOff, nil)
	p.Observer = obs
	go p.Accept()
	defer p.Shutdown()

	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)
	defer src.Close()
	_, _ = src.Write([]byte("A"))
	dst, err := target.Accept()
	assert.Nil(t, err, "the dial happened")
	defer dst.Close()

	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := dst.Read(make([]byte, 1))
	assert.Equal(t, 0, n, "no byte reaches the backend")
	assert.NotNil(t, err, "the backend side is closed")
	_ = src.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = src.Read(make([]byte, 1))
	assert.Equal(t, 0, n)
	assert.NotNil(t, err, "the client is closed without a reply")

	assert.Equal(t, CloseRefused, obs.awaitClose(t))
	assert.Equal(t, []error{nil}, obs.dialed)
	assert.Contains(t, logs.String(), "refused before forwarding: record not durable")
}

func TestObserverSeesLifetimeCap(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer target.Close()
	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}
	obs := newRecordingObserver()
	p, incoming := observedProxy(t, dialer, 300*time.Millisecond, obs)
	defer p.Shutdown()

	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)
	defer src.Close()
	dst, err := target.Accept()
	assert.Nil(t, err)
	defer dst.Close()

	// Neither side sends or closes: only the lifetime cap can end this.
	assert.Equal(t, CloseLifetime, obs.awaitClose(t))
}

// TestCloseAllEndsInFlightConnections: CloseAll closes every connection
// being served, both sides, at once; each observer is told the given
// reason exactly once, whatever the handler's own reason would have been;
// a second CloseAll and the handler's own close path change nothing.
func TestCloseAllEndsInFlightConnections(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer target.Close()
	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}
	obs := newRecordingObserver()
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	p := New(incoming, 5*time.Second, 200*time.Millisecond, 0, 2, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
	p.Observer = obs
	go p.Accept()
	defer p.Shutdown()

	var clients, backends []net.Conn
	for i := 0; i < 2; i++ {
		src, err := net.Dial("tcp", incoming.Addr().String())
		assert.Nil(t, err)
		defer src.Close()
		dst, err := target.Accept()
		assert.Nil(t, err)
		defer dst.Close()
		_, _ = src.Write([]byte("A"))
		_, err = dst.Read(make([]byte, 1))
		assert.Nil(t, err)
		clients, backends = append(clients, src), append(backends, dst)
	}
	assert.Equal(t, 0, len(obs.closed), "both connections are in flight")

	assert.Equal(t, 2, p.CloseAll(CloseHalt))
	assert.Equal(t, CloseHalt, obs.awaitClose(t))
	assert.Equal(t, CloseHalt, obs.awaitClose(t))
	for _, c := range append(clients, backends...) {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := c.Read(make([]byte, 1))
		assert.NotNil(t, err, "both sides of every connection are closed")
	}
	assert.Equal(t, 0, p.CloseAll(CloseHalt), "nothing is left to close")
	time.Sleep(50 * time.Millisecond)
	obs.mu.Lock()
	assert.Equal(t, []CloseReason{CloseHalt, CloseHalt}, obs.closed, "exactly one Closed per connection")
	obs.mu.Unlock()
}

// TestObserverSeesAcceptErrors: every failed Accept is reported to the
// observer with the error and the backoff the loop is about to sleep, one
// report per backoff step, starting at the minimum and doubling.
func TestObserverSeesAcceptErrors(t *testing.T) {
	ln := newCountingFailingListener()
	obs := newRecordingObserver()
	p := proxyForTest(ln, nil)
	p.Observer = obs
	go p.Accept()
	defer func() {
		p.Shutdown()
		p.Wait()
	}()
	time.Sleep(120 * time.Millisecond)
	obs.mu.Lock()
	reported := append([]acceptFailure(nil), obs.acceptErrors...)
	obs.mu.Unlock()
	if len(reported) < 3 {
		t.Fatalf("want at least three accept errors reported in 120ms, got %d", len(reported))
	}
	if reported[0].backoff != acceptBackoffMin {
		t.Fatalf("the first backoff is the minimum, got %s", reported[0].backoff)
	}
	for i, r := range reported {
		if r.err == nil || r.err.Error() != "failure for test" {
			t.Fatalf("report %d carries the wrong error: %v", i, r.err)
		}
		if i > 0 && r.backoff != min(reported[i-1].backoff*2, acceptBackoffMax) {
			t.Fatalf("report %d: backoff %s does not follow %s", i, r.backoff, reported[i-1].backoff)
		}
	}
	if calls := ln.count(); len(reported) > calls {
		t.Fatalf("%d reports for %d Accept calls: at most one per failed Accept", len(reported), calls)
	}
}

// slowCloseObserver takes its time in Closed and records when it has
// returned.
type slowCloseObserver struct {
	*recordingObserver
	delay    time.Duration
	returned atomic.Bool
}

func (o *slowCloseObserver) Accepted(conn net.Conn) (ConnObserver, error) {
	if _, err := o.recordingObserver.Accepted(conn); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *slowCloseObserver) Closed(reason CloseReason) {
	time.Sleep(o.delay)
	o.recordingObserver.Closed(reason)
	o.returned.Store(true)
}

// TestWaitReturnsOnlyAfterClosed: Wait does not return while an
// observer's Closed is still running for a connection that drained during
// shutdown, so whatever Closed records is recorded before the caller of
// Wait goes on (ghostunnel closes its trace there).
func TestWaitReturnsOnlyAfterClosed(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer target.Close()
	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}
	obs := &slowCloseObserver{recordingObserver: newRecordingObserver(), delay: 300 * time.Millisecond}
	p, incoming := observedProxy(t, dialer, 0, obs)
	defer p.Shutdown()

	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)
	dst, err := target.Accept()
	assert.Nil(t, err)
	_, _ = src.Write([]byte("A"))
	_, err = dst.Read(make([]byte, 1))
	assert.Nil(t, err)

	// Shut down with the connection in flight, then let it drain.
	p.Shutdown()
	src.Close()
	dst.Close()
	p.Wait()
	assert.True(t, obs.returned.Load(), "Wait returned before the observer's Closed had returned")
}

// stateTamperingObserver blanks the negotiated protocol in the state it is
// handed at the handshake.
type stateTamperingObserver struct {
	*recordingObserver
}

func (o stateTamperingObserver) Accepted(conn net.Conn) (ConnObserver, error) {
	if _, err := o.recordingObserver.Accepted(conn); err != nil {
		return nil, err
	}
	return o, nil
}

func (o stateTamperingObserver) Handshake(state *tls.ConnectionState, err error) {
	state.NegotiatedProtocol = ""
}

// TestObserverCannotAlterTheStateTheProxyActsOn: the state the observer is
// handed at the handshake is its own copy. An observer that rewrites it
// does not change what the proxy decides from the state: an ACME
// TLS-ALPN-01 probe is still refused and never dialed.
func TestObserverCannotAlterTheStateTheProxyActsOn(t *testing.T) {
	cert, _ := selfSignedCert(t)
	rawIncoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	incoming := tls.NewListener(rawIncoming, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"acme-tls/1"},
		MinVersion:   tls.VersionTLS12,
	})
	dialed := make(chan struct{}, 1)
	dialer := func(ctx context.Context) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, errors.New("must not be reached")
	}
	obs := stateTamperingObserver{newRecordingObserver()}
	p := New(incoming, 5*time.Second, 200*time.Millisecond, 0, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
	p.Observer = obs
	go p.Accept()
	defer p.Shutdown()

	client, err := tls.Dial("tcp", incoming.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"acme-tls/1"},
		MinVersion:         tls.VersionTLS12,
	})
	assert.Nil(t, err)
	if err == nil {
		defer client.Close()
	}

	assert.Equal(t, CloseRefused, obs.awaitClose(t))
	select {
	case <-dialed:
		t.Fatal("an ACME probe must not be dialed, whatever the observer did to its state")
	default:
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	assert.Empty(t, obs.dialed, "Dialed is never reached for an ACME probe")
}
