/*-
 * Copyright 2019 Square Inc.
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

package certloader

import (
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// Listener holds a *net.Listener, wrapping incoming connections in TLS,
// overriding Accept() to make sure we reload the trust bundle on new incoming
// connections. This allows for reloading the CA bundle at runtime without
// restarting the listener.
type Listener struct {
	net.Listener

	config TLSServerConfig
}

// NewListener creates a new TLS listener that wraps the given net.Listener.
func NewListener(listener net.Listener, config TLSServerConfig) *Listener {
	return &Listener{
		Listener: listener,
		config:   config,
	}
}

// Accept waits for and returns the next TLS-wrapped connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(c, l.config.GetServerConfig()), nil
}

// SetDeadline bounds Accept on the wrapped listener, when that listener
// supports a deadline (net.TCPListener and net.UnixListener do); otherwise
// it is an error, so a caller that relies on the deadline can tell.
func (l *Listener) SetDeadline(t time.Time) error {
	if dl, ok := l.Listener.(interface{ SetDeadline(time.Time) error }); ok {
		return dl.SetDeadline(t)
	}
	return errors.New("certloader: the wrapped listener has no deadline")
}
