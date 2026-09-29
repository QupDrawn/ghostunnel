/*-
 * Copyright 2015 Square Inc.
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
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	metrics "github.com/rcrowley/go-metrics"
	sem "golang.org/x/sync/semaphore"
)

// ProxyProtocolMode controls PROXY protocol v2 header generation.
type ProxyProtocolMode int

const (
	// ProxyProtocolOff disables PROXY protocol headers.
	ProxyProtocolOff ProxyProtocolMode = iota
	// ProxyProtocolConn sends connection info (src/dst IP+port) only, no TLVs.
	ProxyProtocolConn
	// ProxyProtocolTLS sends connection info + TLS metadata (version, ALPN, SNI) without client cert details.
	ProxyProtocolTLS
	// ProxyProtocolTLSFull sends connection info + all TLVs including client certificate.
	ProxyProtocolTLSFull
)

var (
	openCounter             = metrics.GetOrRegisterCounter("conn.open", metrics.DefaultRegistry)
	connTimeoutCounter      = metrics.GetOrRegisterCounter("conn.timeout", metrics.DefaultRegistry)
	totalCounter            = metrics.GetOrRegisterCounter("accept.total", metrics.DefaultRegistry)
	successCounter          = metrics.GetOrRegisterCounter("accept.success", metrics.DefaultRegistry)
	errorCounter            = metrics.GetOrRegisterCounter("accept.error", metrics.DefaultRegistry)
	handshakeTimeoutCounter = metrics.GetOrRegisterCounter("accept.timeout", metrics.DefaultRegistry)
	handshakeTimer          = metrics.GetOrRegisterTimer("conn.handshake", metrics.DefaultRegistry)
	connTimer               = metrics.GetOrRegisterTimer("conn.lifetime", metrics.DefaultRegistry)

	// defaultMetrics wraps the package-level handles registered above on the
	// default registry. New uses it when a caller passes nil, preserving the
	// historical behavior of reporting to metrics.DefaultRegistry.
	defaultMetrics = &Metrics{
		OpenCounter:             openCounter,
		ConnTimeoutCounter:      connTimeoutCounter,
		TotalCounter:            totalCounter,
		SuccessCounter:          successCounter,
		ErrorCounter:            errorCounter,
		HandshakeTimeoutCounter: handshakeTimeoutCounter,
		HandshakeTimer:          handshakeTimer,
		ConnTimer:               connTimer,
	}
)

// Metrics holds the go-metrics handles updated on the connection hot path.
// Injecting the handles (instead of reading package globals) lets the caller
// decide, once at startup, whether to collect at all: pass LiveMetrics to
// record against a registry, or NilMetrics to make every update a no-op when no
// metrics sink is configured. The metric names are part of Ghostunnel's
// exported surface and must not change.
type Metrics struct {
	OpenCounter             metrics.Counter // conn.open
	ConnTimeoutCounter      metrics.Counter // conn.timeout
	TotalCounter            metrics.Counter // accept.total
	SuccessCounter          metrics.Counter // accept.success
	ErrorCounter            metrics.Counter // accept.error
	HandshakeTimeoutCounter metrics.Counter // accept.timeout
	HandshakeTimer          metrics.Timer   // conn.handshake
	ConnTimer               metrics.Timer   // conn.lifetime
}

// LiveMetrics registers the connection metrics under their canonical names on
// the given registry and returns handles that record to it. Registration is
// idempotent (GetOrRegister), so repeated calls with the same registry return
// the same underlying handles.
func LiveMetrics(registry metrics.Registry) *Metrics {
	return &Metrics{
		OpenCounter:             metrics.GetOrRegisterCounter("conn.open", registry),
		ConnTimeoutCounter:      metrics.GetOrRegisterCounter("conn.timeout", registry),
		TotalCounter:            metrics.GetOrRegisterCounter("accept.total", registry),
		SuccessCounter:          metrics.GetOrRegisterCounter("accept.success", registry),
		ErrorCounter:            metrics.GetOrRegisterCounter("accept.error", registry),
		HandshakeTimeoutCounter: metrics.GetOrRegisterCounter("accept.timeout", registry),
		HandshakeTimer:          metrics.GetOrRegisterTimer("conn.handshake", registry),
		ConnTimer:               metrics.GetOrRegisterTimer("conn.lifetime", registry),
	}
}

// NilMetrics returns metrics handles whose updates are all no-ops. Use it when
// no metrics sink is configured so the connection hot path spends nothing
// updating contended timers; nothing observes the registry in that case anyway.
func NilMetrics() *Metrics {
	return &Metrics{
		OpenCounter:             metrics.NilCounter{},
		ConnTimeoutCounter:      metrics.NilCounter{},
		TotalCounter:            metrics.NilCounter{},
		SuccessCounter:          metrics.NilCounter{},
		ErrorCounter:            metrics.NilCounter{},
		HandshakeTimeoutCounter: metrics.NilCounter{},
		HandshakeTimer:          metrics.NilTimer{},
		ConnTimer:               metrics.NilTimer{},
	}
}

const (
	// LogConnections will log messages about open/closed connections.
	LogConnections = 1
	// LogConnectionErrors will log errors encountered during backend dialing, other errors (after handshake).
	LogConnectionErrors = 2
	// LogHandshakeErrors will log errors with new connections before/during handshake.
	LogHandshakeErrors = 4
	// LogEverything will log all things.
	LogEverything = LogHandshakeErrors | LogConnectionErrors | LogConnections
)

// Logger is used by this package to log messages
type Logger interface {
	Printf(format string, v ...any)
}

// DialFunc represents a function that can dial a backend/destination for forwarding connections.
type DialFunc func(context.Context) (net.Conn, error)

// Proxy will take incoming connections from a listener and forward them to
// a backend through the given dialer.
type Proxy struct {
	// Listener to accept connections on.
	Listener net.Listener
	// ConnectTimeout, CloseTimeout limit time to execute connects/close connections.
	ConnectTimeout, CloseTimeout time.Duration
	// MaxConnLifetime is the max lifetime for any connection, regardless of circumstances.
	MaxConnLifetime time.Duration
	// Dial function to reach backend to forward connections to.
	Dial DialFunc
	// Logger is used to log information messages about connections, errors.
	Logger Logger
	// Observer, when set, is told about every accepted connection and may
	// refuse it before it is served. Nil (the default) changes nothing.
	Observer Observer

	// CopyBufferSize is the size in bytes of each buffer the copy loops
	// move bytes with, one per direction per connection, drawn from a pool.
	// Zero means DefaultCopyBufferSize. It changes only how many bytes each
	// read and write moves, never which bytes go where. Set before Accept.
	CopyBufferSize int
	// SocketBufferSize, when positive, is set as the kernel send and
	// receive buffer size (SO_SNDBUF and SO_RCVBUF) on every accepted
	// client socket and every backend socket. Zero (the default) leaves
	// the operating system's default. Set before Accept.
	SocketBufferSize int
	// WarmBackendConnections, when positive, keeps up to this many
	// pre-dialed connections to the backend open and idle, so that a
	// served connection takes one instead of dialing on its own path; the
	// pool refills in the background. Zero (the default) dials for every
	// connection. See warmpool.go for what the backend observes.
	// Set before Accept.
	WarmBackendConnections int
	// WarmBackendIdle is how long a pooled backend connection may stay
	// idle before it is closed and replaced. Zero means
	// DefaultWarmBackendIdle. Set before Accept.
	WarmBackendIdle time.Duration

	// Logging flags
	loggerFlags int
	// Enable HAproxy's PROXY protocol
	// see: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	proxyProtocol ProxyProtocolMode
	// Internal wait group to keep track of outstanding handlers.
	handlers *sync.WaitGroup
	// Semaphore to limit the max. number of connections.
	connSemaphore semaphore
	// Context & associated cancel func
	context context.Context
	cancel  context.CancelFunc
	// Guards Shutdown so the cancel/Close/Done sequence runs exactly once,
	// even under concurrent callers. handlers.Done() is not idempotent, so a
	// bare context.Err() check-then-act would let two goroutines both call
	// Done() and drive the WaitGroup counter negative (panic).
	shutdownOnce sync.Once
	// Pool for buffers
	pool sync.Pool
	// warm is the pool of pre-dialed backend connections, started by Accept
	// when WarmBackendConnections is positive, else nil.
	warmMu sync.Mutex
	warm   *warmPool
	// Metrics handles for the connection hot path. Either live (recording to a
	// registry) or no-op (NilMetrics) when no metrics sink is configured.
	metrics *Metrics
	// live is every connection accepted and not yet closed, so that CloseAll
	// can end all of them at once.
	liveMu sync.Mutex
	live   map[*liveConn]struct{}
	// lastIteration is when the accept loop last came round (unix
	// nanoseconds, 0 before it first ran), and listenerClosed is set for
	// good once Accept reported the listener closed: the two facts a health
	// check reads.
	lastIteration  atomic.Int64
	listenerClosed atomic.Bool
}

// LastIteration is when the accept loop last came round, or the zero time
// before it first ran. The loop bounds every wait by acceptDeadline, so a
// healthy loop comes round at least that often with nothing to accept.
func (p *Proxy) LastIteration() time.Time {
	ns := p.lastIteration.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// ListenerClosed reports whether Accept has returned net.ErrClosed, which
// is for good, other than through Shutdown.
func (p *Proxy) ListenerClosed() bool {
	return p.listenerClosed.Load()
}

// ShuttingDown reports whether Shutdown has been called.
func (p *Proxy) ShuttingDown() bool {
	return p.context.Err() != nil
}

// liveConn is one accepted connection in the registry: the client side, the
// backend side once dialed, and the reason CloseAll forced on it, if any,
// which the handler reports in place of its own.
type liveConn struct {
	mu      sync.Mutex
	client  net.Conn
	backend net.Conn
	forced  *CloseReason
}

// track registers an accepted connection until untrack.
func (p *Proxy) track(client net.Conn) *liveConn {
	c := &liveConn{client: client}
	p.liveMu.Lock()
	p.live[c] = struct{}{}
	p.liveMu.Unlock()
	return c
}

func (p *Proxy) untrack(c *liveConn) {
	p.liveMu.Lock()
	delete(p.live, c)
	p.liveMu.Unlock()
}

// setBackend records the dialed backend; if the connection was already
// forced closed in the meantime the backend is closed too, at once.
func (c *liveConn) setBackend(backend net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backend = backend
	if c.forced != nil {
		_ = backend.Close()
	}
}

// force closes both sides with the given reason. Closing is idempotent
// against the connection's own close path: net.Conn.Close tolerates a
// second call, and the handler reports the forced reason exactly once, in
// its own Closed callback.
func (c *liveConn) force(reason CloseReason) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forced != nil {
		return
	}
	c.forced = &reason
	_ = c.client.Close()
	if c.backend != nil {
		_ = c.backend.Close()
	}
}

// reason is the forced reason if CloseAll ended the connection, else the
// handler's own.
func (c *liveConn) reason(own CloseReason) CloseReason {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forced != nil {
		return *c.forced
	}
	return own
}

// CloseAll closes every connection accepted and not yet closed, at once,
// and returns how many it closed. Each connection's observer is told the
// given reason, once, when its handler ends. A connection accepted after
// this call is not affected; the caller decides on it at accept.
func (p *Proxy) CloseAll(reason CloseReason) int {
	p.liveMu.Lock()
	conns := make([]*liveConn, 0, len(p.live))
	for c := range p.live {
		conns = append(conns, c)
	}
	p.liveMu.Unlock()
	for _, c := range conns {
		c.force(reason)
	}
	// The pooled backend connections are ended too: they are not accepted
	// connections, so they are not counted, and the pool stays empty until a
	// connection is served again.
	if w := p.warmPool(); w != nil {
		w.drain(false)
	}
	return len(conns)
}

// PROXY protocol v2 client flag constants (from spec section 2.2.5).
const (
	pp2ClientSSL      = 0x01
	pp2ClientCertConn = 0x02
	pp2ClientCertSess = 0x04
)

func transportProtocol(c net.Conn) proxyproto.AddressFamilyAndProtocol {
	switch addr := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return proxyproto.TCPv4
		}
		return proxyproto.TCPv6
	case *net.UnixAddr:
		// Unix-domain listeners are valid PROXY protocol carriers; without
		// this case, go-proxyproto's formatVersion2 rejects the *net.UnixAddr
		// SourceAddr/DestinationAddr as ErrInvalidAddress and every connection
		// fails per-connection at WriteTo time.
		return proxyproto.UnixStream
	}
	return proxyproto.UNSPEC
}

func proxyProtoHeader(c net.Conn, tlsState *tls.ConnectionState, mode ProxyProtocolMode) (*proxyproto.Header, error) {
	h := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: transportProtocol(c),
		SourceAddr:        c.RemoteAddr(),
		DestinationAddr:   c.LocalAddr(),
	}

	if tlsState != nil && mode >= ProxyProtocolTLS {
		tlvs, err := buildTLVs(tlsState, mode)
		if err != nil {
			return nil, fmt.Errorf("building PROXY protocol TLVs: %w", err)
		}
		if len(tlvs) > 0 {
			if err := h.SetTLVs(tlvs); err != nil {
				return nil, fmt.Errorf("setting PROXY protocol TLVs: %w", err)
			}
		}
	}

	return h, nil
}

// buildTLVs constructs the top-level TLV list from TLS connection state.
func buildTLVs(state *tls.ConnectionState, mode ProxyProtocolMode) ([]proxyproto.TLV, error) {
	var tlvs []proxyproto.TLV

	// PP2_TYPE_ALPN
	if state.NegotiatedProtocol != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_ALPN,
			Value: []byte(state.NegotiatedProtocol),
		})
	}

	// PP2_TYPE_AUTHORITY (SNI)
	if state.ServerName != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_AUTHORITY,
			Value: []byte(state.ServerName),
		})
	}

	// PP2_TYPE_SSL with nested sub-TLVs
	sslTLV, err := buildSSLTLV(state, mode)
	if err != nil {
		return nil, err
	}
	tlvs = append(tlvs, sslTLV)

	return tlvs, nil
}

// buildSSLTLV constructs the PP2_TYPE_SSL TLV with its 5-byte sub-header
// and nested sub-TLVs containing TLS connection metadata.
func buildSSLTLV(state *tls.ConnectionState, mode ProxyProtocolMode) (proxyproto.TLV, error) {
	var subTLVs []proxyproto.TLV

	// Always include TLS version
	subTLVs = append(subTLVs, proxyproto.TLV{
		Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
		Value: []byte(tls.VersionName(state.Version)),
	})

	// Client certificate fields (only in TLSFull mode and if a cert was presented)
	if mode == ProxyProtocolTLSFull && len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		if cert.Subject.CommonName != "" {
			subTLVs = append(subTLVs, proxyproto.TLV{
				Type:  proxyproto.PP2_SUBTYPE_SSL_CN,
				Value: []byte(cert.Subject.CommonName),
			})
		}

		// Full DER-encoded client certificate (extension, not in HAProxy spec)
		subTLVs = append(subTLVs, proxyproto.TLV{
			Type:  proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT,
			Value: cert.Raw,
		})
	}

	// Build 5-byte sub-header: 1 byte flags + 4 bytes verify result
	var flags byte = pp2ClientSSL
	if mode == ProxyProtocolTLSFull && len(state.PeerCertificates) > 0 {
		// Set both flags: Ghostunnel doesn't distinguish connection-level vs
		// session-level (resumed) cert presentation — the cert was verified
		// on this connection either way.
		flags |= pp2ClientCertConn | pp2ClientCertSess
	}
	var header [5]byte
	header[0] = flags
	binary.BigEndian.PutUint32(header[1:5], 0) // verify=0, cert already verified by ghostunnel

	// Encode sub-TLVs and append after the 5-byte header
	subTLVBytes, err := proxyproto.JoinTLVs(subTLVs)
	if err != nil {
		return proxyproto.TLV{}, fmt.Errorf("encoding SSL sub-TLVs: %w", err)
	}

	value := make([]byte, len(header)+len(subTLVBytes))
	copy(value, header[:])
	copy(value[len(header):], subTLVBytes)

	return proxyproto.TLV{Type: proxyproto.PP2_TYPE_SSL, Value: value}, nil
}

// DefaultCopyBufferSize is the copy buffer size when CopyBufferSize is zero.
// See BenchmarkBulkThroughput for the measurement it was chosen by.
const DefaultCopyBufferSize = 64 << 10

// copyBufferSize is the configured copy buffer size, or the default.
func (p *Proxy) copyBufferSize() int {
	if p.CopyBufferSize > 0 {
		return p.CopyBufferSize
	}
	return DefaultCopyBufferSize
}

// setSocketBuffers applies SocketBufferSize, if set, to the socket under
// conn: a TLS connection is unwrapped to the socket it runs on. A
// connection that has no such buffers (a pipe, a test stub) is left alone.
func (p *Proxy) setSocketBuffers(conn net.Conn) {
	size := p.SocketBufferSize
	if size <= 0 || conn == nil {
		return
	}
	for {
		inner, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		next := inner.NetConn()
		if next == nil || next == conn {
			break
		}
		conn = next
	}
	if rb, ok := conn.(interface{ SetReadBuffer(int) error }); ok {
		_ = rb.SetReadBuffer(size)
	}
	if wb, ok := conn.(interface{ SetWriteBuffer(int) error }); ok {
		_ = wb.SetWriteBuffer(size)
	}
}

// New creates a new proxy.
func New(
	listener net.Listener,
	connectTimeout, closeTimeout, maxConnLifetime time.Duration,
	maxConcurrentConnections int64,
	dial DialFunc,
	logger Logger,
	loggerFlags int,
	proxyProtocol ProxyProtocolMode,
	connMetrics *Metrics) *Proxy {

	// A nil handle means "use the default registry" (the historical behavior);
	// callers that want to skip collection pass NilMetrics explicitly.
	if connMetrics == nil {
		connMetrics = defaultMetrics
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		Listener:        listener,
		ConnectTimeout:  connectTimeout,
		CloseTimeout:    closeTimeout,
		MaxConnLifetime: maxConnLifetime,
		Dial:            dial,
		Logger:          logger,
		loggerFlags:     loggerFlags,
		proxyProtocol:   proxyProtocol,
		handlers:        &sync.WaitGroup{},
		context:         ctx,
		cancel:          cancel,
		metrics:         connMetrics,
		live:            make(map[*liveConn]struct{}),
	}
	p.pool.New = func() any {
		b := make([]byte, p.copyBufferSize())
		return &b
	}

	if maxConcurrentConnections > 0 {
		p.connSemaphore = sem.NewWeighted(maxConcurrentConnections)
	} else {
		p.connSemaphore = &unlimitedSemaphore{}
	}

	// Add one handler to the wait group, so that Wait() will always block until
	// Shutdown() is called even if the proxy hasn't started yet. This prevents
	// a race condition if someone calls Accept() in a Goroutine and then immediately
	// calls Wait() on the proxy object.
	p.handlers.Add(1)
	return p
}

// Shutdown tells the proxy to close the listener & stop accepting connections.
// Safe to call concurrently and repeatedly; the shutdown work runs exactly once.
func (p *Proxy) Shutdown() {
	p.shutdownOnce.Do(func() {
		p.cancel()
		p.Listener.Close()
		if w := p.warmPool(); w != nil {
			w.drain(true)
		}
		p.handlers.Done()
	})
}

// startWarmPool starts the pool of pre-dialed backend connections if
// WarmBackendConnections asks for one, once, and never after Shutdown.
func (p *Proxy) startWarmPool() {
	if p.WarmBackendConnections <= 0 || p.Dial == nil {
		return
	}
	p.warmMu.Lock()
	defer p.warmMu.Unlock()
	if p.warm != nil || p.context.Err() != nil {
		return
	}
	idle := p.WarmBackendIdle
	if idle <= 0 {
		idle = DefaultWarmBackendIdle
	}
	p.warm = newWarmPool(p, p.WarmBackendConnections, idle)
}

// warmPool is the running pool, or nil.
func (p *Proxy) warmPool() *warmPool {
	p.warmMu.Lock()
	defer p.warmMu.Unlock()
	return p.warm
}

// dialBackend is the backend connection for an accepted client: a pooled
// one when the warm pool has a live one, else a fresh dial. Either way
// the socket buffers are applied.
func (p *Proxy) dialBackend(ctx context.Context) (net.Conn, error) {
	if w := p.warmPool(); w != nil {
		if conn := w.take(); conn != nil {
			return conn, nil
		}
	}
	conn, err := p.Dial(ctx)
	if err != nil {
		return nil, err
	}
	p.setSocketBuffers(conn)
	return conn, nil
}

// Wait until the proxy is shut down (listener closed, connections drained,
// and the observer's Closed returned for every one of them).
// This function will block even if the proxy isn't in the accept loop yet,
// so it's safe to concurrently run Accept() in a Goroutine and then immediately
// call Wait().
func (p *Proxy) Wait() {
	p.handlers.Wait()
}

// Backoff bounds for Accept errors. Bounds mirror net/http.Server.Serve.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = 1 * time.Second
)

// acceptDeadline bounds every wait in the accept loop (the semaphore and
// Accept itself), so the loop comes round at least this often and
// LastIteration says whether it is alive.
const acceptDeadline = 1 * time.Second

// Accept incoming connections and spawn Go routines to handle them and forward
// the data to the backend. Will stop accepting connections if Shutdown() is called.
// Run this in a Goroutine, call Wait() to block on proxy shutdown/connection drain.
func (p *Proxy) Accept() {
	// acceptBackoff is the current sleep delay after an Accept error. It
	// starts at zero, jumps to acceptBackoffMin on first error, doubles up
	// to acceptBackoffMax, and resets to zero after a successful Accept. This
	// prevents a hot loop on persistent errors like fd exhaustion (EMFILE).
	var acceptBackoff time.Duration

	p.startWarmPool()

	for {
		p.lastIteration.Store(time.Now().UnixNano())

		// Acquire semaphore, to limit max concurrent connections. The wait is
		// bounded by acceptDeadline so the loop keeps coming round, and
		// keeps saying so, while every slot is taken.
		acquireCtx, cancelAcquire := context.WithTimeout(p.context, acceptDeadline)
		err := p.connSemaphore.Acquire(acquireCtx, 1)
		cancelAcquire()
		if err != nil {
			if p.context.Err() != nil {
				// Context was cancelled -- we're done here
				return
			}
			continue
		}

		// Reserve the handler slot BEFORE the blocking Accept(). This guarantees
		// that any connection Accept() hands back is already accounted for in the
		// WaitGroup, so Shutdown()'s Done() (which balances New()'s guard Add)
		// can never transiently drive the counter to zero while an accepted-but-
		// not-yet-registered connection is outstanding.
		p.handlers.Add(1)

		// Wait for new connection, for at most acceptDeadline where the
		// listener can be told so, so the loop comes round with nothing to
		// accept.
		if dl, ok := p.Listener.(interface{ SetDeadline(time.Time) error }); ok {
			_ = dl.SetDeadline(time.Now().Add(acceptDeadline))
		}
		conn, err := p.Listener.Accept()
		if err != nil {
			// No connection to handle: release the reserved slot.
			p.handlers.Done()

			// Check if we're supposed to stop
			if err := p.context.Err(); err != nil {
				return
			}

			p.connSemaphore.Release(1)
			if isTimeoutError(err) {
				// The loop's own deadline: nothing to accept, nothing wrong.
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				p.listenerClosed.Store(true)
			}

			p.metrics.ErrorCounter.Inc(1)
			p.logConditional(LogConnectionErrors, "error accepting connection: %s", err)

			// Back off before retrying so we don't spin at 100% CPU on
			// persistent accept errors (e.g. fd exhaustion).
			if acceptBackoff == 0 {
				acceptBackoff = acceptBackoffMin
			} else {
				acceptBackoff = min(acceptBackoff*2, acceptBackoffMax)
			}
			if p.Observer != nil {
				p.Observer.AcceptError(err, acceptBackoff)
			}
			select {
			case <-time.After(acceptBackoff):
			case <-p.context.Done():
				return
			}
			continue
		}
		// Successful accept: reset backoff.
		acceptBackoff = 0

		// Handler slot reserved above; the handler's cleanup defer calls Done().
		go func() {
			// Record the connection lifetime explicitly rather than via
			// Timer.Time: a no-op timer's Time() would not run the closure at
			// all, which would skip connection handling when metrics are off.
			// UpdateSince is deferred first so it fires last (after the close
			// defer below), matching Timer.Time's "measure the whole handler".
			startTime := time.Now()
			defer p.metrics.ConnTimer.UpdateSince(startTime)

			p.metrics.OpenCounter.Inc(1)
			p.metrics.TotalCounter.Inc(1)

			// The observer, if any, follows this connection; reason is why it
			// ended, reported once the connection is closed, unless CloseAll
			// ended it first, in which case its reason is reported instead.
			// The slot is released before Closed, so the close line's sync
			// does not hold it; the handler is done only once Closed has
			// returned, so Wait never returns before the close is recorded.
			var observer ConnObserver
			reason := CloseEOF
			live := p.track(conn)
			defer func() {
				conn.Close()
				p.untrack(live)
				p.metrics.OpenCounter.Dec(1)
				p.connSemaphore.Release(1)
				if observer != nil {
					observer.Closed(live.reason(reason))
				}
				p.handlers.Done()
			}()

			p.setSocketBuffers(conn)

			if p.Observer != nil {
				var err error
				observer, err = p.Observer.Accepted(conn)
				if err != nil {
					// Refused before anything was read: closed by the defer
					// above, never dialed, and not followed any further.
					observer = nil
					p.metrics.ErrorCounter.Inc(1)
					return
				}
			}

			ctx, cancel := context.WithTimeout(p.context, p.ConnectTimeout)
			defer cancel()

			err := forceHandshake(ctx, conn, p.metrics)
			// The connection state is taken once, here: a server
			// connection's state is fixed once its handshake has finished,
			// and everything below reads this copy. The observer is handed
			// a copy of its own, so nothing it does to it reaches the
			// checks below.
			var state *tls.ConnectionState
			if tlsConn, ok := conn.(*tls.Conn); ok {
				s := tlsConn.ConnectionState()
				state = &s
			}
			if observer != nil && state != nil {
				own := *state
				observer.Handshake(&own, err)
			}
			if err != nil {
				p.metrics.ErrorCounter.Inc(1)
				p.logConditional(LogHandshakeErrors, "error on TLS handshake from %s: %s", conn.RemoteAddr(), err)
				reason = CloseRefused
				if p.context.Err() != nil {
					reason = CloseShutdown
				}
				return
			}

			// TLS-ALPN-01 challenge probes complete the handshake to deliver
			// the challenge certificate, but carry no application data and
			// must never reach the backend. The handshake itself ran with
			// ClientAuth relaxed (see certloader/acmetlsconfig.go); refusing
			// to proxy ensures that relaxation cannot become an mTLS bypass.
			if isACMEChallenge(state) {
				p.logConditional(LogConnections, "completed ACME TLS-ALPN-01 challenge from %s; not forwarding to backend", conn.RemoteAddr())
				reason = CloseRefused
				return
			}

			backend, err := p.dialBackend(ctx)
			if observer != nil {
				// Dialed may refuse the connection here, before the backend
				// is registered, before the PROXY header and before fuse:
				// no byte has been forwarded in either direction when it
				// returns. On a failed dial the dial error decides below.
				if derr := observer.Dialed(backend, err); derr != nil && err == nil {
					if backend != nil {
						backend.Close()
					}
					p.metrics.ErrorCounter.Inc(1)
					p.logConditional(LogConnectionErrors, "connection from %s refused before forwarding: %s", conn.RemoteAddr(), derr)
					reason = CloseRefused
					if p.context.Err() != nil {
						reason = CloseShutdown
					}
					return
				}
			}
			if err != nil {
				p.metrics.ErrorCounter.Inc(1)
				p.logConditional(LogConnectionErrors, "error on dial: %s", err)
				reason = CloseError
				if p.context.Err() != nil {
					reason = CloseShutdown
				}
				return
			}
			live.setBackend(backend)

			if p.proxyProtocol != ProxyProtocolOff {
				h, err := proxyProtoHeader(conn, state, p.proxyProtocol)
				if err != nil {
					p.metrics.ErrorCounter.Inc(1)
					p.logConditional(LogConnectionErrors, "error building proxy header: %s", err)
					backend.Close()
					reason = CloseError
					return
				}
				if _, err = h.WriteTo(backend); err != nil {
					p.metrics.ErrorCounter.Inc(1)
					p.logConditional(LogConnectionErrors, "error writing proxy header: %s", err)
					backend.Close()
					reason = CloseError
					return
				}
			}

			p.metrics.SuccessCounter.Inc(1)
			reason = p.fuse(conn, backend)
		}()
	}
}

// isACMEChallenge reports whether the state of an already-handshaken
// connection (nil for one that is not TLS) negotiated the TLS-ALPN-01
// challenge protocol from RFC 8737. Such a connection is an ACME validator
// probe and must not be proxied to the backend: the relaxed ClientAuth in
// certloader/acmetlsconfig.go is scoped to making the handshake complete,
// not to authorizing application data.
func isACMEChallenge(state *tls.ConnectionState) bool {
	return state != nil && state.NegotiatedProtocol == "acme-tls/1"
}

// Force handshake. Handshake usually happens on first read/write, but we want
// to force it to make sure we can control the timeout for it. Otherwise,
// unauthenticated clients would be able to open connections and leave them
// hanging forever. Going through the handshake verifies that clients have a
// valid client cert and are allowed to talk to us.
func forceHandshake(ctx context.Context, conn net.Conn, m *Metrics) error {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		startTime := time.Now()
		defer m.HandshakeTimer.UpdateSince(startTime)

		err := tlsConn.HandshakeContext(ctx)
		if isTimeoutError(err) {
			// If we timed out, increment timeout metric
			m.HandshakeTimeoutCounter.Inc(1)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// Fuse connections together. Returns why the connection ended: the lifetime
// cap, an error, or one side finishing (a close-timeout after a half-close
// counts as the latter; before any side finishes the only deadline set is
// the lifetime cap).
func (p *Proxy) fuse(client, backend net.Conn) CloseReason {
	// Copy from client -> backend, and from backend -> client
	start := time.Now()
	p.logConnectionMessage("opening", client, backend, -1, -1, time.Time{})

	// If set by user, set max conn lifetime for client/backend.
	if p.MaxConnLifetime > 0 {
		setDeadline(client, p.MaxConnLifetime)
		setDeadline(backend, p.MaxConnLifetime)
	}

	// For TCP and UNIX sockets, copyData calls closeRead and closeWrite for the
	// src/dst respectively. For TCP sockets, this will call the shutdown syscall
	// to block read/writes (and send a FIN packet). However, we still need to
	// free up the FDs after we're done by calling close.
	defer func() {
		_ = client.Close()
		_ = backend.Close()
	}()

	type copied struct {
		n   int64
		err error
	}
	returnedC := make(chan copied)
	go func() {
		n, err := p.copyData(client, backend)
		returnedC <- copied{n, err}
	}()
	forwarded, forwardErr := p.copyData(backend, client)
	returned := <-returnedC

	p.logConnectionMessage("closed", client, backend, forwarded, returned.n, start)

	reason := CloseEOF
	for _, err := range []error{forwardErr, returned.err} {
		switch {
		case err == nil:
		case isTimeoutError(err):
			if p.MaxConnLifetime > 0 && time.Since(start) >= p.MaxConnLifetime {
				return CloseLifetime
			}
		default:
			reason = CloseError
		}
	}
	return reason
}

// Copy data between two connections. The returned error is the copy error,
// if any, other than the peer closing; those are the normal end of a copy.
func (p *Proxy) copyData(dst net.Conn, src net.Conn) (written int64, err error) {
	// When we're done copying the data, we close the read/write sides of the
	// src/dst respectively. This uses the shutdown system call to send a FIN
	// packet to the other end of the connection. By only closing the read/write
	// sides specifically, we retain the ability to forward or return data in a
	// case where a client has only half-closed the connection.
	//
	// We also set a deadline on the entire connection in order to avoid resource
	// leaks. Without the deadline, a misbehaving client could keep a connection
	// open by not reading/writing any data on their end, which would cause the
	// other copyData Go routine to wait forever. Setting a deadline forces the
	// other Go routine to unblock and return with an i/o timeout error. We could
	// also solve this by by monitoring for POLLHUP but doing so would tie up an
	// OS thread.
	//
	// See: https://github.com/golang/go/issues/67337#issuecomment-2123352634
	defer func() {
		closeRead(src)
		closeWrite(dst)
		setDeadline(src, p.CloseTimeout)
		setDeadline(dst, p.CloseTimeout)
	}()

	// Get a buffer for copy from the pool of shared buffers, to reduce allocs.
	// A pooled buffer of another size (the size was changed after some were
	// pooled) is dropped for a fresh one of the configured size.
	//
	// Reusing a buffer another connection filled is equivalent to a fresh
	// one because the buffer is scratch that io.CopyBuffer writes into before
	// it reads from: each round reads n bytes from src into buf[:n] and
	// writes exactly buf[:n] to dst, so what reaches dst is only what src
	// gave in this call; the stale bytes beyond n are never forwarded. The
	// buffer is held by this direction alone from Get to Put, so no two
	// copies share one. TestCopyDataPooledBufferIsScratch and
	// TestCopyDataSequentialConnectionsForwardOwnBytes hold it to that.
	buf := p.pool.Get().(*[]byte)
	if want := p.copyBufferSize(); len(*buf) != want {
		b := make([]byte, want)
		buf = &b
	}
	defer p.pool.Put(buf)

	// Note: We wrap src and dst in io.Writer and io.Reader structs respectively,
	// to hide the WriteTo and ReadFrom functions on TCPConn and UnixConn.
	//
	// Why do we do this? Because CopyBuffer will prefer calling WriteTo/ReadFrom
	// if possible, in order to use splice or sendfile for better perf. However,
	// this fails if one of the arguments is tls.Conn, because TLS connections
	// have to go through user space to perform cryptographic operations.
	//
	// But this creates a problem: If splice/sendfile fail, then to still perform
	// the copy the stdlib will recursively call io.Copy. But in doing so it
	// can't provide the buffer we've allocated and thus it allocates a new one,
	// throwing away the original buf we passed in. To avoid this, we hide the
	// WriteTo and ReadFrom methods.
	//
	// Note that this is not easy to catch in testing: You might be tempted to
	// use net.Pipe() for tests, but pipes don't implement WriteTo/ReadFrom and
	// thus won't run into this issue.
	//
	// See: https://github.com/golang/go/issues/16474
	// See: https://github.com/golang/go/issues/67074
	written, err = io.CopyBuffer(
		struct{ io.Writer }{dst},
		struct{ io.Reader }{src},
		*buf)

	if err != nil && isClosedConnectionError(err) {
		err = nil
	}
	if err != nil {
		// We don't log individual "read from closed connection" errors, because
		// we already have a log statement showing that a pipe has been closed.
		if isTimeoutError(err) {
			p.metrics.ConnTimeoutCounter.Inc(1)
		}
		p.logConditional(LogConnectionErrors, "error during copy: %s", err)
	}

	return written, err
}

// Log information message about connection
func (p *Proxy) logConnectionMessage(action string, dst net.Conn, src net.Conn, forwarded, returned int64, start time.Time) {
	if (p.loggerFlags & LogConnections) == 0 {
		return
	}
	p.Logger.Printf(
		"%s pipe: %s:%s [%s] <-> %s:%s [%s] %s",
		action,
		dst.RemoteAddr().Network(),
		dst.RemoteAddr().String(),
		peerCertificatesString(dst),
		src.RemoteAddr().Network(),
		src.RemoteAddr().String(),
		peerCertificatesString(src),
		connStatsString(forwarded, returned, time.Since(start)),
	)
}

func (p *Proxy) logConditional(flag int, msg string, args ...any) {
	if (p.loggerFlags & flag) > 0 {
		p.Logger.Printf(msg, args...)
	}
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded)
}

// errWSAEConnReset is WSAECONNRESET on Windows, the equivalent of
// syscall.ECONNRESET on Unix systems. While syscall.ECONNRESET is defined on
// Windows as well, it's an APPLICATION_ERROR-based value, not the WSA errno.
const errWSAEConnReset = syscall.Errno(10054)

func isClosedConnectionError(err error) bool {
	// Abrupt peer termination (RST / broken pipe) is routine for a proxy —
	// impatient clients, health checks, and idle keep-alive resets all cause
	// it — and is not actionable, so treat it the same as an orderly close.
	// errors.Is unwraps net.OpError, so these match whether or not the error is
	// wrapped in one. On Windows a socket reset carries the WSA errno
	// (errWSAEConnReset) rather than the POSIX syscall.ECONNRESET, so match both.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, errWSAEConnReset) {
		return true
	}

	opErr := &net.OpError{}
	if errors.As(err, &opErr) {
		return (opErr.Op == "read" || opErr.Op == "readfrom" || opErr.Op == "write" || opErr.Op == "writeto") &&
			strings.Contains(err.Error(), "closed network connection")
	}
	return strings.Contains(err.Error(), "closed pipe")
}

func closeRead(conn net.Conn) {
	switch c := conn.(type) {
	case *net.TCPConn:
		_ = c.CloseRead()
	case *net.UnixConn:
		_ = c.CloseRead()
	case *tls.Conn:
		// tls.Conn has no CloseRead(): we can't shut down only the read
		// side without tearing down the whole connection. Do nothing here
		// and let the CloseTimeout deadline (set by copyData's defer) unblock
		// and reap the connection. Closing it here would kill the opposite
		// (still-live) write direction, dropping in-flight return traffic.
	default:
		_ = c.Close()
	}
}

func closeWrite(conn net.Conn) {
	switch c := conn.(type) {
	case *net.TCPConn:
		_ = c.CloseWrite()
	case *net.UnixConn:
		_ = c.CloseWrite()
	case *tls.Conn:
		// CloseWrite sends a TLS close_notify alert to the peer (a clean
		// half-close of the write side) without closing the underlying
		// socket, so the opposite direction can keep reading/forwarding.
		_ = c.CloseWrite()
	default:
		_ = c.Close()
	}
}

func setDeadline(conn net.Conn, timeout time.Duration) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
}
