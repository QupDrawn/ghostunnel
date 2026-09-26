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
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	spiffetest "github.com/ghostunnel/ghostunnel/certloader/internal/test"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// switchPolicy is a policy.Policy whose Reload swaps in the next prepared
// query, standing in for a policy file that changed on disk.
type switchPolicy struct {
	mu   sync.Mutex
	cur  *rego.PreparedEvalQuery
	next *rego.PreparedEvalQuery
}

func (p *switchPolicy) Reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.next != nil {
		p.cur = p.next
	}
	return nil
}

func (p *switchPolicy) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	p.mu.Lock()
	query := p.cur
	p.mu.Unlock()
	return query.Eval(ctx, options...)
}

func prepareQuery(t testing.TB, module string) *rego.PreparedEvalQuery {
	t.Helper()
	query, err := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())
	require.NoError(t, err)
	return &query
}

const allowGopherPolicy = `package policy
default allow := false
allow if {
	input.certificate.Subject.CommonName == "gopher"
}
`

const denyAllPolicy = `package policy
default allow := false
`

// mtlsFixture is an in-process server behind certloader's config and a
// client with a certificate the server's CA issued.
type mtlsFixture struct {
	listener *Listener
	client   *tls.Config
	// clockOffset is added to the server's clock (tls.Config.Time), so a
	// test can move the server past a certificate's validity.
	clockOffset atomic.Int64
}

// newMTLSFixture builds the server from TLSConfigSourceFromCertificate with
// verify as its VerifyPeerCertificate callback, exactly as ghostunnel's
// server mode does, and a client presenting a leaf with common name cn.
func newMTLSFixture(t testing.TB, cn string, verify func([][]byte, [][]*x509.Certificate) error) *mtlsFixture {
	t.Helper()
	ca := spiffetest.NewCA(t, spiffeid.RequireTrustDomainFromString("example.org"))
	serverChain, serverKey := ca.CreateX509Certificate(spiffetest.WithIPAddresses(net.IPv4(127, 0, 0, 1)))
	clientChain, clientKey := ca.CreateX509Certificate(spiffetest.WithSubject(pkix.Name{CommonName: cn}))
	pool := spiffetest.NewCertPool(ca.X509Authorities())

	serverCert := &tls.Certificate{Certificate: [][]byte{serverChain[0].Raw}, PrivateKey: serverKey}
	clientCert := tls.Certificate{Certificate: [][]byte{clientChain[0].Raw}, PrivateKey: clientKey}

	f := &mtlsFixture{
		client: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCert},
		},
	}
	base := &tls.Config{
		ClientAuth:            tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: verify,
		Time:                  func() time.Time { return time.Now().Add(time.Duration(f.clockOffset.Load())) },
	}
	source := TLSConfigSourceFromCertificate(&staticCertificate{cert: serverCert, pool: pool}, log.Default())
	serverConfig, err := source.GetServerConfig(base)
	require.NoError(t, err)

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f.listener = NewListener(inner, serverConfig)
	t.Cleanup(func() { f.listener.Close() })
	return f
}

// TestCertSourceResumedSessionIsServedFromVerifyCache: with a VerifyCache
// bound to the ACL, the full handshake is verified once, each resumption
// (re-checked by the VerifyConnection hook with the chain stored in the
// ticket) is served from the cache, and after a policy reload the next
// resumption is verified afresh and refused.
func TestCertSourceResumedSessionIsServedFromVerifyCache(t *testing.T) {
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

			f := newMTLSFixture(t, "gopher", acl.VerifyPeerCertificateServer)
			results := serveHandshakes(t, f.listener)
			f.client.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			f.client.MinVersion = tc.version
			f.client.MaxVersion = tc.version
			addr := f.listener.Addr().String()

			state, err := dialAndDrain(t, addr, f.client)
			require.NoError(t, err)
			require.False(t, state.DidResume)
			require.NoError(t, awaitServerResult(t, results).err)
			hits, misses := cache.Stats()
			assert.Equal(t, uint64(0), hits)
			assert.Equal(t, uint64(1), misses, "the full handshake is verified")

			for i := 0; i < 2; i++ {
				state, err = dialAndDrain(t, addr, f.client)
				require.NoError(t, err)
				require.True(t, state.DidResume, "handshake should resume the session")
				require.NoError(t, awaitServerResult(t, results).err)
			}
			hits, misses = cache.Stats()
			assert.Equal(t, uint64(2), hits, "the resumed sessions' stored chain hashes to the same key")
			assert.Equal(t, uint64(1), misses)

			// The reload path: the policy changes, then the cache is told.
			require.NoError(t, pol.Reload())
			cache.Invalidate()

			_, err = dialAndDrain(t, addr, f.client)
			require.Error(t, err, "resumed session must be re-verified under the new policy and refused")
			require.Error(t, awaitServerResult(t, results).err)
			hits, misses = cache.Stats()
			assert.Equal(t, uint64(2), hits)
			assert.Equal(t, uint64(2), misses, "after the reload the chain is verified again")
		})
	}
}

// TestCertSourceExpiredClientIsRefusedBeforeTheCache: crypto/tls checks the
// chain's validity against the config's clock on every handshake, full or
// resumed, before the verifier is consulted, so an expired client is refused
// whatever the cache remembers. This documents where expiry is enforced
// for a chain crypto/tls built; the cache's own clock check is tested at
// the cache.
func TestCertSourceExpiredClientIsRefusedBeforeTheCache(t *testing.T) {
	cache := auth.NewVerifyCache(16)
	acl := auth.ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)

	f := newMTLSFixture(t, "gopher", acl.VerifyPeerCertificateServer)
	results := serveHandshakes(t, f.listener)
	f.client.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	addr := f.listener.Addr().String()

	_, err := dialAndDrain(t, addr, f.client)
	require.NoError(t, err)
	require.NoError(t, awaitServerResult(t, results).err)
	_, misses := cache.Stats()
	require.Equal(t, uint64(1), misses)

	// The server's clock moves past the client certificate's validity.
	f.clockOffset.Store(int64(24 * 365 * time.Hour))

	_, err = dialAndDrain(t, addr, f.client)
	require.Error(t, err)
	result := awaitServerResult(t, results)
	require.Error(t, result.err)
	assert.Contains(t, result.err.Error(), "expired", "crypto/tls refuses the expired chain")
	hits, misses := cache.Stats()
	assert.Equal(t, uint64(0), hits, "nothing was served from the cache")
	assert.Equal(t, uint64(1), misses, "the verifier was not consulted")
}
