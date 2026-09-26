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

package certloader

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/ghostunnel/ghostunnel/auth"
	spiffetest "github.com/ghostunnel/ghostunnel/certloader/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verifyMode is who verifies the tunnel client's chain: crypto/tls under
// RequireAndVerifyClientCert, or the ACL under RequireAnyClientCert
// (GetServerConfigVerifying).
type verifyMode string

const (
	goVerifies  verifyMode = "crypto/tls verifies"
	aclVerifies verifyMode = "the ACL verifies"
)

var verifyModes = []verifyMode{goVerifies, aclVerifies}

// swappableCertificate is a Certificate whose trust store can be replaced
// between connections, standing in for a reload of the CA bundle.
type swappableCertificate struct {
	cert *tls.Certificate
	pool atomic.Pointer[x509.CertPool]
}

func (s *swappableCertificate) Reload() error         { return nil }
func (s *swappableCertificate) GetIdentifier() string { return "swappable" }
func (s *swappableCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.cert, nil
}
func (s *swappableCertificate) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return s.cert, nil
}
func (s *swappableCertificate) GetTrustStore() *x509.CertPool { return s.pool.Load() }

// testPKI is a root, an intermediate under it, the server's certificate
// under the root and a pool trusting the root.
type testPKI struct {
	root, inter       *x509.Certificate
	rootKey, interKey crypto.Signer
	pool              *x509.CertPool
	server            *tls.Certificate
}

// newTestPKI builds the PKI with the intermediate valid over interWindow
// (the root and the server certificate are valid for two days around now).
func newTestPKI(t testing.TB, interNotBefore, interNotAfter time.Time) *testPKI {
	t.Helper()
	now := time.Now()
	root, rootKey := spiffetest.CreateCACertificate(t, nil, nil, spiffetest.WithLifetime(now.Add(-24*time.Hour), now.Add(24*time.Hour)))
	inter, interKey := spiffetest.CreateCACertificate(t, root, rootKey, spiffetest.WithLifetime(interNotBefore, interNotAfter))
	server, serverKey := spiffetest.CreateX509Certificate(t, root, rootKey,
		spiffetest.WithIPAddresses(net.IPv4(127, 0, 0, 1)),
		spiffetest.WithLifetime(now.Add(-24*time.Hour), now.Add(24*time.Hour)))
	return &testPKI{
		root: root, inter: inter, rootKey: rootKey, interKey: interKey,
		pool:   spiffetest.NewCertPool([]*x509.Certificate{root}),
		server: &tls.Certificate{Certificate: [][]byte{server.Raw}, PrivateKey: serverKey},
	}
}

// clientLeaf issues a client leaf with common name cn from the
// intermediate, valid over the window, and returns it with the
// intermediate as the certificate the client presents.
func (p *testPKI) clientLeaf(t testing.TB, cn string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	leaf, key := spiffetest.CreateX509Certificate(t, p.inter, p.interKey,
		spiffetest.WithSubject(pkix.Name{CommonName: cn}), spiffetest.WithLifetime(notBefore, notAfter))
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, p.inter.Raw}, PrivateKey: key}
}

// chainFixture is an in-process tunnel listener built by certloader with
// one of the two verify modes, and its server-side handshake results.
type chainFixture struct {
	listener    *Listener
	results     <-chan handshakeResult
	config      TLSServerConfig
	cert        *swappableCertificate
	clockOffset atomic.Int64
}

// newChainFixture is newChainListener with the server-side handshake
// results collected (serveHandshakes).
func newChainFixture(t testing.TB, mode verifyMode, acl auth.ACL, pki *testPKI) *chainFixture {
	t.Helper()
	f := newChainListener(t, mode, acl, pki)
	f.results = serveHandshakes(t, f.listener)
	return f
}

// newChainListener builds the listener from TLSConfigSourceFromCertificate
// as ghostunnel's server mode does for each mode: under goVerifies the base
// config carries RequireAndVerifyClientCert and the ACL's plain callback;
// under aclVerifies the base carries only RequireAndVerifyClientCert
// (buildServerConfig's default) and GetServerConfigVerifying wires the ACL. Nothing accepts
// on the listener yet.
func newChainListener(t testing.TB, mode verifyMode, acl auth.ACL, pki *testPKI) *chainFixture {
	t.Helper()
	f := &chainFixture{cert: &swappableCertificate{cert: pki.server}}
	f.cert.pool.Store(pki.pool)
	base := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		Time:       func() time.Time { return time.Now().Add(time.Duration(f.clockOffset.Load())) },
	}
	source := TLSConfigSourceFromCertificate(f.cert, log.Default())
	var err error
	switch mode {
	case goVerifies:
		base.VerifyPeerCertificate = acl.VerifyPeerCertificateServer
		f.config, err = source.GetServerConfig(base)
	case aclVerifies:
		f.config, err = GetServerConfigVerifying(source, base, acl)
	}
	require.NoError(t, err)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f.listener = NewListener(inner, f.config)
	t.Cleanup(func() { f.listener.Close() })
	return f
}

func (f *chainFixture) addr() string { return f.listener.Addr().String() }

// clientConfig is a client presenting cert, trusting the PKI's root. The
// certificate is presented whatever the server's certificate_authorities
// hint says (a Go client given Certificates withholds one that does not
// chain to the hint, so a chain the server must refuse would never reach
// it); the hint is the same in both modes, as ClientCAs is.
func clientConfig(pki *testPKI, cert tls.Certificate, version uint16) *tls.Config {
	return &tls.Config{
		RootCAs: pki.pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		MinVersion: version,
		MaxVersion: version,
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestChainVerifyingHandshakeMatchesCryptoTLS: for the matrix of client
// chains, a handshake against the config where the ACL verifies the chain
// accepts and refuses exactly what a handshake against the config where
// crypto/tls verifies it did, with the same server-side error (the error
// the log and the ring record), on TLS 1.2 and 1.3.
//
// The alert the client sees is pinned too. crypto/tls sends
// bad_certificate for any error a VerifyPeerCertificate callback returns,
// while for its own verification it sends unknown_ca for an unknown
// authority (an unknown CA, a missing intermediate) and
// certificate_expired for a validity failure. Those two classes therefore
// reach the client as bad_certificate where the ACL verifies; a wrong
// extended key usage is bad_certificate in both modes. The server's own
// record of the refusal is the same in every case.
func TestChainVerifyingHandshakeMatchesCryptoTLS(t *testing.T) {
	now := time.Now()
	pki := newTestPKI(t, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	other := newTestPKI(t, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	valid := pki.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(time.Hour))
	serverOnly, serverOnlyKey := spiffetest.CreateX509Certificate(t, pki.inter, pki.interKey,
		spiffetest.WithSubject(pkix.Name{CommonName: "gopher"}), spiffetest.WithLifetime(now.Add(-time.Hour), now.Add(time.Hour)))
	serverOnly = spiffetest.CreateCertificate(t, &x509.Certificate{
		SerialNumber: serverOnly.SerialNumber,
		Subject:      serverOnly.Subject,
		NotBefore:    serverOnly.NotBefore,
		NotAfter:     serverOnly.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, pki.inter, serverOnlyKey.Public(), pki.interKey)

	cases := []struct {
		name string
		cert tls.Certificate
		// the server-side error both modes must report; "" when accepted
		serverErr string
		// the alert the client sees where crypto/tls verifies and where the ACL does
		clientGo, clientACL string
	}{
		{name: "valid", cert: valid},
		{name: "valid, not allowed", cert: pki.clientLeaf(t, "nobody", now.Add(-time.Hour), now.Add(time.Hour)),
			serverErr: "unauthorized: invalid principal, or principal not allowed",
			clientGo:  "remote error: tls: bad certificate", clientACL: "remote error: tls: bad certificate"},
		{name: "expired leaf", cert: pki.clientLeaf(t, "gopher", now.Add(-2*time.Hour), now.Add(-time.Hour)),
			serverErr: "tls: failed to verify certificate: x509: certificate has expired or is not yet valid",
			clientGo:  "remote error: tls: expired certificate", clientACL: "remote error: tls: bad certificate"},
		{name: "not yet valid", cert: pki.clientLeaf(t, "gopher", now.Add(time.Hour), now.Add(2*time.Hour)),
			serverErr: "tls: failed to verify certificate: x509: certificate has expired or is not yet valid",
			clientGo:  "remote error: tls: expired certificate", clientACL: "remote error: tls: bad certificate"},
		{name: "unknown CA", cert: other.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(time.Hour)),
			serverErr: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
			clientGo:  "remote error: tls: unknown certificate authority", clientACL: "remote error: tls: bad certificate"},
		{name: "missing intermediate", cert: tls.Certificate{Certificate: valid.Certificate[:1], PrivateKey: valid.PrivateKey},
			serverErr: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
			clientGo:  "remote error: tls: unknown certificate authority", clientACL: "remote error: tls: bad certificate"},
		{name: "wrong EKU", cert: tls.Certificate{Certificate: [][]byte{serverOnly.Raw, pki.inter.Raw}, PrivateKey: serverOnlyKey},
			serverErr: "tls: failed to verify certificate: x509: certificate specifies an incompatible key usage",
			clientGo:  "remote error: tls: bad certificate", clientACL: "remote error: tls: bad certificate"},
	}
	for _, version := range []struct {
		name string
		id   uint16
	}{{"TLS1.2", tls.VersionTLS12}, {"TLS1.3", tls.VersionTLS13}} {
		t.Run(version.name, func(t *testing.T) {
			acl := auth.ACL{AllowedCNs: []string{"gopher"}}
			goFix := newChainFixture(t, goVerifies, acl, pki)
			aclFix := newChainFixture(t, aclVerifies, acl, pki)
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					config := clientConfig(pki, tc.cert, version.id)
					_, clientGo := dialAndDrain(t, goFix.addr(), config)
					serverGo := awaitServerResult(t, goFix.results)
					_, clientACL := dialAndDrain(t, aclFix.addr(), config)
					serverACL := awaitServerResult(t, aclFix.results)

					if tc.serverErr == "" {
						assert.NoError(t, serverGo.err)
						assert.NoError(t, serverACL.err)
						assert.NoError(t, clientGo)
						assert.NoError(t, clientACL)
						return
					}
					require.Error(t, serverGo.err, "the matrix expects a refusal")
					require.Error(t, serverACL.err)
					assert.Contains(t, serverGo.err.Error(), tc.serverErr)
					assert.Contains(t, serverACL.err.Error(), tc.serverErr)
					// The wording is the same up to the clock in a validity
					// error, which is the time of each verification.
					assert.Equal(t, errPrefix(serverGo.err), errPrefix(serverACL.err), "the server records the same refusal")
					assert.Equal(t, tc.clientGo, errString(clientGo), "the alert where crypto/tls verifies")
					assert.Equal(t, tc.clientACL, errString(clientACL), "the alert where the ACL verifies")
				})
			}
		})
	}
}

// errPrefix is the error's text up to a ": current time" clause.
func errPrefix(err error) string {
	s := err.Error()
	for i := 0; i+len(": current time") <= len(s); i++ {
		if s[i:i+len(": current time")] == ": current time" {
			return s[:i]
		}
	}
	return s
}

// TestChainVerifyingHandshakeSkipsVerificationOnRepeat: with a cache
// bound, a repeat client is served from the cache on a full handshake and
// on a resumption alike, and after a policy reload the next handshake is
// verified afresh and refused; the same shape as the test for the config
// where crypto/tls verifies.
func TestChainVerifyingHandshakeSkipsVerificationOnRepeat(t *testing.T) {
	now := time.Now()
	pki := newTestPKI(t, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	client := pki.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(time.Hour))
	for _, tc := range []struct {
		name    string
		version uint16
	}{
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := auth.NewVerifyCache(16)
			pol := &switchPolicy{cur: prepareQuery(t, allowGopherPolicy), next: prepareQuery(t, denyAllPolicy)}
			acl := auth.ACL{AllowOPAQuery: pol, OPAQueryTimeout: 10 * time.Second}.WithVerifyCache(cache)
			f := newChainFixture(t, aclVerifies, acl, pki)
			config := clientConfig(pki, client, tc.version)

			// Two full handshakes: verified once, served once.
			for i := 0; i < 2; i++ {
				state, err := dialAndDrain(t, f.addr(), config)
				require.NoError(t, err)
				require.False(t, state.DidResume)
				result := awaitServerResult(t, f.results)
				require.NoError(t, result.err)
				assert.Empty(t, result.state.VerifiedChains, "crypto/tls built no chain")
				require.Len(t, result.state.PeerCertificates, 2)
			}
			hits, misses := cache.Stats()
			assert.Equal(t, uint64(1), hits)
			assert.Equal(t, uint64(1), misses)

			// Resumptions: the stored certificates are re-verified from the cache.
			config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			state, err := dialAndDrain(t, f.addr(), config)
			require.NoError(t, err)
			require.False(t, state.DidResume)
			require.NoError(t, awaitServerResult(t, f.results).err)
			for i := 0; i < 2; i++ {
				state, err = dialAndDrain(t, f.addr(), config)
				require.NoError(t, err)
				require.True(t, state.DidResume, "handshake should resume the session")
				require.NoError(t, awaitServerResult(t, f.results).err)
			}
			hits, misses = cache.Stats()
			assert.Equal(t, uint64(4), hits)
			assert.Equal(t, uint64(1), misses, "x509.Verify ran once in all")

			require.NoError(t, pol.Reload())
			cache.Invalidate()
			_, err = dialAndDrain(t, f.addr(), config)
			require.Error(t, err, "resumed session must be re-verified under the new policy and refused")
			require.Error(t, awaitServerResult(t, f.results).err)
			hits, misses = cache.Stats()
			assert.Equal(t, uint64(4), hits)
			assert.Equal(t, uint64(2), misses)
		})
	}
}

// TestChainVerifyingExpiryIsRefusedOnResumption: a client whose chain
// expires between the full handshake and a resumption (the server's clock
// advanced) is refused, in both modes, with the same error. With the leaf
// expired crypto/tls declines the resumption itself and the full
// handshake that follows is refused, in both modes. With an intermediate
// expired and the leaf still valid, crypto/tls declines the resumption
// only when it verified the chain; where the ACL verifies, the session
// resumes and the VerifyConnection hook refuses it, because the remembered
// verification's window is the whole chain's and the config's clock has
// left it: nothing is served from the cache and x509.Verify refuses.
func TestChainVerifyingExpiryIsRefusedOnResumption(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name          string
		interNotAfter time.Duration
		leafNotAfter  time.Duration
		offset        time.Duration
	}{
		{"leaf expires", 12 * time.Hour, time.Hour, 2 * time.Hour},
		{"intermediate expires", 10 * time.Minute, time.Hour, 30 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newTestPKI(t, now.Add(-time.Hour), now.Add(tc.interNotAfter))
			client := pki.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(tc.leafNotAfter))
			for _, mode := range verifyModes {
				t.Run(string(mode), func(t *testing.T) {
					cache := auth.NewVerifyCache(16)
					acl := auth.ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)
					f := newChainFixture(t, mode, acl, pki)
					config := clientConfig(pki, client, tls.VersionTLS13)
					config.ClientSessionCache = tls.NewLRUClientSessionCache(1)

					_, err := dialAndDrain(t, f.addr(), config)
					require.NoError(t, err)
					require.NoError(t, awaitServerResult(t, f.results).err)
					_, misses := cache.Stats()
					require.Equal(t, uint64(1), misses)

					f.clockOffset.Store(int64(tc.offset))
					_, err = dialAndDrain(t, f.addr(), config)
					require.Error(t, err, "the client is refused")
					result := awaitServerResult(t, f.results)
					require.Error(t, result.err)
					assert.Contains(t, result.err.Error(), "tls: failed to verify certificate: x509: certificate has expired or is not yet valid")
					hits, misses := cache.Stats()
					assert.Equal(t, uint64(0), hits, "nothing was served from the cache")
					if mode == aclVerifies {
						assert.Equal(t, uint64(2), misses, "x509.Verify ran again and refused")
						if tc.name == "intermediate expires" {
							assert.True(t, result.state.DidResume, "crypto/tls resumed; the hook refused")
						}
					} else {
						assert.Equal(t, uint64(1), misses, "crypto/tls refused before the callback")
					}
				})
			}
		})
	}
}

// TestChainVerifyingReloadRebindsTheTrustStore: a new trust store makes a
// new config, whose callback is bound to the new pool: a client under the
// old root is refused as unknown and one under the new root accepted, and
// ClientCAs is the new pool, in both modes.
func TestChainVerifyingReloadRebindsTheTrustStore(t *testing.T) {
	now := time.Now()
	old := newTestPKI(t, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	fresh := newTestPKI(t, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	oldClient := old.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(time.Hour))
	freshClient := fresh.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(time.Hour))
	for _, mode := range verifyModes {
		t.Run(string(mode), func(t *testing.T) {
			cache := auth.NewVerifyCache(16)
			acl := auth.ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)
			f := newChainFixture(t, mode, acl, old)
			assert.Same(t, old.pool, f.config.GetServerConfig().ClientCAs)

			_, err := dialAndDrain(t, f.addr(), clientConfig(old, oldClient, tls.VersionTLS13))
			require.NoError(t, err)
			require.NoError(t, awaitServerResult(t, f.results).err)

			// The reload: the trust store changes, then the cache is told.
			f.cert.pool.Store(fresh.pool)
			cache.Invalidate()
			assert.Same(t, fresh.pool, f.config.GetServerConfig().ClientCAs)

			_, err = dialAndDrain(t, f.addr(), clientConfig(old, oldClient, tls.VersionTLS13))
			require.Error(t, err)
			result := awaitServerResult(t, f.results)
			require.Error(t, result.err)
			assert.Contains(t, result.err.Error(), "x509: certificate signed by unknown authority")

			_, err = dialAndDrain(t, f.addr(), clientConfig(old, freshClient, tls.VersionTLS13))
			require.NoError(t, err)
			require.NoError(t, awaitServerResult(t, f.results).err)
		})
	}
}

// TestChainVerifyingChainsForTheRing: after a handshake where the ACL
// verified, the connection state carries no verified chains, and the ACL
// reports the chain it verified under the presented certificates, on
// which ServerRule names the rule as it did on crypto/tls's chains.
func TestChainVerifyingChainsForTheRing(t *testing.T) {
	now := time.Now()
	pki := newTestPKI(t, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	client := pki.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(time.Hour))
	for _, mode := range verifyModes {
		t.Run(string(mode), func(t *testing.T) {
			acl := auth.ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(auth.NewVerifyCache(16))
			f := newChainFixture(t, mode, acl, pki)
			_, err := dialAndDrain(t, f.addr(), clientConfig(pki, client, tls.VersionTLS13))
			require.NoError(t, err)
			result := awaitServerResult(t, f.results)
			require.NoError(t, result.err)
			raw := make([][]byte, len(result.state.PeerCertificates))
			for i, cert := range result.state.PeerCertificates {
				raw[i] = cert.Raw
			}
			chains, ok := acl.VerifiedChainsFor(raw)
			require.True(t, ok)
			require.Len(t, chains, 1)
			require.Len(t, chains[0], 3)
			assert.Equal(t, client.Certificate[0], chains[0][0].Raw)
			assert.Equal(t, pki.inter.Raw, chains[0][1].Raw)
			assert.Equal(t, pki.root.Raw, chains[0][2].Raw)
			assert.Equal(t, "allow-cn", acl.ServerRule(raw, chains))
			if mode == aclVerifies {
				assert.Empty(t, result.state.VerifiedChains)
				assert.Equal(t, "none", acl.ServerRule(raw, result.state.VerifiedChains), "why the ring must ask the ACL")
			} else {
				assert.Equal(t, chains[0][0].Raw, result.state.VerifiedChains[0][0].Raw)
			}
		})
	}
}

// recordingSource is a TLSConfigSource that is not a ClientVerifyingSource
// and records the base it was given, standing for the Workload API source.
type recordingSource struct {
	base *tls.Config
}

func (r *recordingSource) Reload() error  { return nil }
func (r *recordingSource) CanServe() bool { return true }
func (r *recordingSource) GetClientConfig(base *tls.Config) (TLSClientConfig, error) {
	return nil, ErrACMENotSupportedClient
}
func (r *recordingSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	r.base = base
	return &staticServerConfig{config: base}, nil
}

type staticServerConfig struct{ config *tls.Config }

func (s *staticServerConfig) GetServerConfig() *tls.Config { return s.config }

// TestGetServerConfigVerifyingShape: the config each source builds under
// the ACL's verification, without a handshake: ClientAuth is
// RequireAnyClientCert, ClientCAs is the trust store, the callback and
// the resumption hook are installed, the config's clock is what the
// callback verifies on; in pin mode the config is what it was; a source
// that is not a ClientVerifyingSource gets the plain callback; a base
// with a callback of its own is refused.
func TestGetServerConfigVerifyingShape(t *testing.T) {
	now := time.Now()
	pki := newTestPKI(t, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	client := pki.clientLeaf(t, "gopher", now.Add(-time.Hour), now.Add(time.Hour))
	acl := auth.ACL{AllowedCNs: []string{"gopher"}}
	clock := func() time.Time { return now.Add(2 * time.Hour) } // the leaf has expired on it
	base := &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, Time: clock}

	check := func(t *testing.T, config *tls.Config) {
		t.Helper()
		assert.Equal(t, tls.RequireAnyClientCert, config.ClientAuth)
		assert.Same(t, pki.pool, config.ClientCAs)
		require.NotNil(t, config.VerifyPeerCertificate)
		require.NotNil(t, config.VerifyConnection, "the resumption hook")
		err := config.VerifyPeerCertificate(client.Certificate, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x509: certificate has expired or is not yet valid", "verified on the config's clock")
	}

	t.Run("certificate source", func(t *testing.T) {
		cert := &swappableCertificate{cert: pki.server}
		cert.pool.Store(pki.pool)
		source := TLSConfigSourceFromCertificate(cert, log.Default())
		config, err := GetServerConfigVerifying(source, base, acl)
		require.NoError(t, err)
		check(t, config.GetServerConfig())
		assert.Same(t, config.GetServerConfig(), config.GetServerConfig(), "the config is cached per trust store")
	})

	t.Run("ACME source", func(t *testing.T) {
		magicConfig := certmagic.NewDefault()
		source := &acmeTLSConfigSource{magicConfig: magicConfig, gtACMEConfig: &ACMEConfig{}}
		source.cachedTrustStore.Store(pki.pool)
		config, err := GetServerConfigVerifying(source, base, acl)
		require.NoError(t, err)
		built := config.GetServerConfig()
		check(t, built)
		// The TLS-ALPN-01 probe's relaxed config asks for no certificate in both modes.
		relaxed, err := built.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com", SupportedProtos: []string{"acme-tls/1"}})
		require.NoError(t, err)
		assert.Equal(t, tls.NoClientCert, relaxed.ClientAuth)
		assert.Nil(t, relaxed.ClientCAs)
	})

	t.Run("pin mode", func(t *testing.T) {
		cert := &swappableCertificate{cert: pki.server}
		cert.pool.Store(pki.pool)
		source := TLSConfigSourceFromCertificate(cert, log.Default())
		pins, err := auth.ParseSPKIPins([]string{"sha256:" + spkiDigest(t, client.Certificate[0])})
		require.NoError(t, err)
		config, err := GetServerConfigVerifying(source, base, auth.ACL{AllowedPins: pins})
		require.NoError(t, err)
		built := config.GetServerConfig()
		assert.Equal(t, tls.RequireAnyClientCert, built.ClientAuth)
		assert.Nil(t, built.ClientCAs, "no certificate_authorities hint in pin mode")
		require.NotNil(t, built.VerifyPeerCertificate)
		require.NotNil(t, built.VerifyConnection)
		assert.NoError(t, built.VerifyPeerCertificate(client.Certificate, nil), "the pin, not the chain")
	})

	t.Run("a source that verifies itself", func(t *testing.T) {
		source := &recordingSource{}
		config, err := GetServerConfigVerifying(source, base, acl)
		require.NoError(t, err)
		built := config.GetServerConfig()
		assert.Equal(t, tls.RequireAndVerifyClientCert, built.ClientAuth, "the base is left to the source")
		require.NotNil(t, built.VerifyPeerCertificate)
		assert.EqualError(t, built.VerifyPeerCertificate(client.Certificate, nil), "unauthorized: invalid principal, or principal not allowed", "the plain callback, judging what it is handed")
		assert.Nil(t, base.VerifyPeerCertificate, "the caller's base is not mutated")
	})

	t.Run("base with a callback", func(t *testing.T) {
		source := &recordingSource{}
		withCallback := base.Clone()
		withCallback.VerifyPeerCertificate = acl.VerifyPeerCertificateServer
		_, err := GetServerConfigVerifying(source, withCallback, acl)
		assert.ErrorIs(t, err, ErrBaseHasVerifier)
	})
}

// spkiDigest is the base64 SHA-256 of the certificate's SubjectPublicKeyInfo,
// the digest of an sha256: pin.
func spkiDigest(t testing.TB, certDER []byte) string {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
