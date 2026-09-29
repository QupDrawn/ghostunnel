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
	"crypto/tls"
	"net"
	"time"
)

// Observer is told what happens to every connection the proxy accepts and
// may refuse a connection before it is served. A Proxy without one (the
// default) has nothing added to its connection path.
type Observer interface {
	// Accepted is called on every accepted connection before anything is
	// read from it. A non-nil error refuses the connection: it is closed
	// without a handshake and never reaches the backend, and no further
	// callback is made for it. On nil error the returned ConnObserver, if
	// not nil, follows the connection until it is closed.
	Accepted(conn net.Conn) (ConnObserver, error)
	// AcceptError is called on every failed Accept, with the error and the
	// backoff the accept loop is about to sleep before its next attempt:
	// once per backoff step. It is not called for the loop's own deadline.
	AcceptError(err error, backoff time.Duration)
}

// ConnObserver follows one accepted connection.
type ConnObserver interface {
	// Handshake is called once the TLS handshake on the accepted connection
	// has finished, with the connection state as it stands and the error on
	// failure. It is not called for a plaintext listener.
	Handshake(state *tls.ConnectionState, err error)
	// Dialed is called once the backend dial has finished, with the backend
	// connection or the error, before any byte is forwarded in either
	// direction (the PROXY protocol header included). A non-nil return
	// refuses the connection at that point: the proxy closes both sides
	// without forwarding anything, counts an error, and reports the close
	// as refused. When Dialed returns nil nothing has been forwarded yet
	// either; forwarding begins after it. It is called whether or not the
	// dial succeeded; on a failed dial its return value is not consulted,
	// the connection is closed for the dial error.
	Dialed(backend net.Conn, err error) error
	// Closed is called exactly once, after the connection is closed and
	// before Proxy.Wait can return.
	Closed(reason CloseReason)
}

// CloseReason is why a connection ended.
type CloseReason int

const (
	// CloseEOF: the client or the backend finished.
	CloseEOF CloseReason = iota
	// CloseError: an error while dialing, writing the PROXY header or copying.
	CloseError
	// CloseLifetime: MaxConnLifetime expired.
	CloseLifetime
	// CloseShutdown: the proxy was shut down before the connection was set up.
	CloseShutdown
	// CloseRefused: the handshake failed, or the proxy declined to forward.
	CloseRefused
	// CloseHalt: the connection was closed by CloseAll while in flight,
	// because serving was refused after it had been accepted.
	CloseHalt
)

func (r CloseReason) String() string {
	switch r {
	case CloseEOF:
		return "eof"
	case CloseError:
		return "error"
	case CloseLifetime:
		return "lifetime"
	case CloseShutdown:
		return "shutdown"
	case CloseRefused:
		return "refused"
	case CloseHalt:
		return "halt"
	}
	return "unknown"
}
