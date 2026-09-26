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
	"crypto/x509"
	"errors"
	"time"
)

// TLSConfigSource is used to configure client or server TLS. It supports hot reloading.
type TLSConfigSource interface {
	// Reload will reload the TLS configuration. If reloading fails, the
	// existing configuration will be used. The client and server config
	// interface returned by GetClientConfig and GetServerConfig should reflect
	// any new configuration.
	Reload() error

	// CanServe returns true if the source can return configuration appropriate
	// for server roles (see GetServerConfig)
	CanServe() bool

	// GetClientConfig returns a TLSClientConfig interface that can be used to
	// obtain TLS client configuration. The base configuration is cloned and
	// used as a base for all returned TLS configuration.
	GetClientConfig(base *tls.Config) (TLSClientConfig, error)

	// GetServerConfig returns a TLSServerConfig interface that can be used to
	// obtain TLS server configuration. The base configuration is cloned and
	// used as a base for all returned TLS configuration. If the source is
	// not appropriate for use as a server, an error is returned.
	GetServerConfig(base *tls.Config) (TLSServerConfig, error)
}

// TLSClientConfig is an interface for obtaining TLS client configuration.
type TLSClientConfig interface {
	// GetClientConfig returns a TLS configuration for use as a TLS client. It
	// is safe to call concurrently.
	GetClientConfig() *tls.Config
}

// TLSServerConfig is an interface for obtaining TLS server configuration.
type TLSServerConfig interface {
	// GetServerConfig returns a TLS configuration for use as a TLS server. It
	// is safe to call concurrently.
	GetServerConfig() *tls.Config
}

// ClientVerifier is the tunnel's client verifier, as auth.ACL implements
// it: the VerifyPeerCertificate callback that judges a client crypto/tls
// verified, whether it authenticates by SPKI pin instead of a chain, and a
// callback bound to one config's trust material and clock that verifies
// the client's chain itself with the options crypto/tls would use (see
// auth.ACL.VerifyPeerCertificateServerFor).
type ClientVerifier interface {
	PinningEnabled() bool
	VerifyPeerCertificateServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	VerifyPeerCertificateServerFor(roots *x509.CertPool, now func() time.Time) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

// ClientVerifyingSource is a TLSConfigSource that can hand the
// verification of client chains to the tunnel's ClientVerifier: the
// certificate and ACME sources. The Workload API source does not; it
// verifies through go-spiffe.
type ClientVerifyingSource interface {
	GetServerConfigVerifying(base *tls.Config, verifier ClientVerifier) (TLSServerConfig, error)
}

// ErrBaseHasVerifier is returned by GetServerConfigVerifying when the base
// config already carries a VerifyPeerCertificate callback: the verifier is
// the callback, and a second one would be silently replaced.
var ErrBaseHasVerifier = errors.New("certloader: the base config already has a VerifyPeerCertificate callback; the verifier is the callback")

// GetServerConfigVerifying is source.GetServerConfig for the tunnel
// listener, with verifier as its client verifier. On a source that can
// (ClientVerifyingSource), the configs it returns have ClientAuth
// RequireAnyClientCert, ClientCAs the trust store, and as
// VerifyPeerCertificate the verifier's callback bound to that trust store
// and the config's clock, which verifies the client's chain exactly as
// crypto/tls would have under RequireAndVerifyClientCert and then applies
// the verifier's rules; with a VerifyCache bound to the verifier a repeat
// client skips the chain verification. In pin mode the config is
// RequireAnyClientCert, no ClientCAs, the verifier's plain callback.
// On any other source the base is given the verifier's plain callback and
// crypto/tls (or the source) verifies the chain. The base must
// not carry a VerifyPeerCertificate callback of its own.
func GetServerConfigVerifying(source TLSConfigSource, base *tls.Config, verifier ClientVerifier) (TLSServerConfig, error) {
	if base == nil {
		base = new(tls.Config)
	}
	if base.VerifyPeerCertificate != nil {
		return nil, ErrBaseHasVerifier
	}
	if verifying, ok := source.(ClientVerifyingSource); ok {
		return verifying.GetServerConfigVerifying(base, verifier)
	}
	base = base.Clone()
	base.VerifyPeerCertificate = verifier.VerifyPeerCertificateServer
	return source.GetServerConfig(base)
}

// verifyingBase is the base config for a source that hands chain
// verification to the verifier: in pin mode, the pin-mode config
// (RequireAnyClientCert, no ClientCAs); otherwise RequireAnyClientCert with no
// callback yet, which the builder binds per trust store (bindClientVerifier).
func verifyingBase(base *tls.Config, verifier ClientVerifier) *tls.Config {
	base = base.Clone()
	base.ClientAuth = tls.RequireAnyClientCert
	if verifier.PinningEnabled() {
		base.VerifyPeerCertificate = verifier.VerifyPeerCertificateServer
	}
	return base
}

// bindClientVerifier finishes a server config built for pool by a source
// that hands chain verification to verifier: ClientCAs is the pool, as it
// is under crypto/tls's own verification (the certificate_authorities hint
// the client sees is unchanged), and VerifyPeerCertificate is the
// verifier's callback bound to that pool and the config's clock. In pin
// mode the config is left as it is: no ClientCAs, the plain callback.
func bindClientVerifier(config *tls.Config, pool *x509.CertPool, verifier ClientVerifier) {
	if verifier.PinningEnabled() {
		return
	}
	now := config.Time
	if now == nil {
		now = time.Now
	}
	config.ClientCAs = pool
	config.VerifyPeerCertificate = verifier.VerifyPeerCertificateServerFor(pool, now)
}

// reverifyResumedSessions installs a VerifyConnection callback on config that
// runs its VerifyPeerCertificate callback again for resumed sessions. Go only
// invokes VerifyPeerCertificate during a full handshake: when a client resumes
// a session it restores the peer certificates and verified chains stored with
// the ticket and re-checks their expiry, but never consults the callback
// again. ghostunnel enforces its access control in that callback, so without
// this a client whose access was withdrawn could keep resuming until the
// ticket keys rotate. The re-check mirrors a full handshake: the stored
// certificates and chains are handed to the same callback, so pin, SPIFFE and
// ACL verification all apply and fail closed on an empty set. Any
// VerifyConnection already on config runs first. A config with no
// VerifyPeerCertificate callback is left alone, as there is nothing to re-run.
func reverifyResumedSessions(config *tls.Config) {
	verify := config.VerifyPeerCertificate
	if verify == nil {
		return
	}
	previous := config.VerifyConnection
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if previous != nil {
			if err := previous(cs); err != nil {
				return err
			}
		}
		if !cs.DidResume {
			return nil
		}
		rawCerts := make([][]byte, len(cs.PeerCertificates))
		for i, cert := range cs.PeerCertificates {
			rawCerts[i] = cert.Raw
		}
		return verify(rawCerts, cs.VerifiedChains)
	}
}
