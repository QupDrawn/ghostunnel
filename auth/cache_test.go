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

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testChain is a CA-signed leaf as the verifier sees it: the raw
// certificates the peer presented (leaf first) and the chain crypto/tls
// built for them.
type testChain struct {
	raw    [][]byte
	chains [][]*x509.Certificate
}

// newTestChain issues a leaf with the given common name and validity from a
// fresh CA and returns it in the verifier's shape.
func newTestChain(t testing.TB, cn string, notBefore, notAfter time.Time) testChain {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notAfter.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return testChain{
		raw:    [][]byte{leafDER},
		chains: [][]*x509.Certificate{{leaf, ca}},
	}
}

func validChain(t testing.TB, cn string) testChain {
	t.Helper()
	return newTestChain(t, cn, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// prepareQuery compiles a policy module exposing data.policy.allow.
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

func assertStats(t *testing.T, cache *VerifyCache, hits, misses uint64) {
	t.Helper()
	gotHits, gotMisses := cache.Stats()
	assert.Equal(t, hits, gotHits, "hits")
	assert.Equal(t, misses, gotMisses, "misses")
}

// TestVerifyCacheHit: the same chain twice is verified once and served
// once, with the same result.
func TestVerifyCacheHit(t *testing.T) {
	chain := validChain(t, "gopher")
	cache := NewVerifyCache(16)
	acl := ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)

	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	assertStats(t, cache, 0, 1)
	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	assertStats(t, cache, 1, 1)
	assert.Equal(t, 1, cache.Len())
}

// TestVerifyCacheClientHit is the same on the client-side verifier, and
// shows the two roles are kept apart: an empty ACL refuses on the server
// side and allows on the client side, for the same chain.
func TestVerifyCacheClientHit(t *testing.T) {
	chain := validChain(t, "gopher")
	cache := NewVerifyCache(16)
	acl := ACL{}.WithVerifyCache(cache)

	require.Error(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	require.NoError(t, acl.VerifyPeerCertificateClient(chain.raw, chain.chains))
	assertStats(t, cache, 0, 2)
	require.Error(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	require.NoError(t, acl.VerifyPeerCertificateClient(chain.raw, chain.chains))
	assertStats(t, cache, 2, 2)
}

// TestVerifyCacheRejectStaysRejected: a refused chain is refused from the
// cache with the very error the verifier returned, and a reload
// (Invalidate) makes the verifier decide again.
func TestVerifyCacheRejectStaysRejected(t *testing.T) {
	chain := validChain(t, "gopher")
	cache := NewVerifyCache(16)
	acl := ACL{AllowedCNs: []string{"someone-else"}}.WithVerifyCache(cache)

	first := acl.VerifyPeerCertificateServer(chain.raw, chain.chains)
	require.EqualError(t, first, "unauthorized: invalid principal, or principal not allowed")
	second := acl.VerifyPeerCertificateServer(chain.raw, chain.chains)
	assert.Same(t, first, second, "the cached decision is the verifier's own error")
	assertStats(t, cache, 1, 1)

	cache.Invalidate()
	assert.Equal(t, 0, cache.Len())
	third := acl.VerifyPeerCertificateServer(chain.raw, chain.chains)
	require.EqualError(t, third, "unauthorized: invalid principal, or principal not allowed")
	assert.NotSame(t, first, third, "after a reload the verifier decided afresh")
	assertStats(t, cache, 1, 2)
}

// TestVerifyCacheReloadInvalidates: after a policy reload the previously
// allowed chain is verified again under the new policy and refused. The
// ACL's own rules never change for the life of a process, so the policy is
// the configuration a reload can tighten.
func TestVerifyCacheReloadInvalidates(t *testing.T) {
	chain := validChain(t, "gopher")
	cache := NewVerifyCache(16)
	pol := &switchPolicy{cur: prepareQuery(t, allowGopherPolicy), next: prepareQuery(t, denyAllPolicy)}
	acl := ACL{AllowOPAQuery: pol, OPAQueryTimeout: 10 * time.Second}.WithVerifyCache(cache)

	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	assertStats(t, cache, 1, 1)

	// The reload path: the policy is reloaded, then the cache is told.
	require.NoError(t, pol.Reload())
	cache.Invalidate()

	err := acl.VerifyPeerCertificateServer(chain.raw, chain.chains)
	require.EqualError(t, err, "unauthorized: invalid principal, or principal not allowed")
	assertStats(t, cache, 1, 2)
}

// TestVerifyCacheExpiryReverifies: a remembered decision is not served
// once the clock leaves the chain's validity window; the verifier decides
// again and its decision is what the caller gets. The verifier here is a
// stub whose answer changes, standing for whatever a fresh verification
// would decide about a chain that has expired.
func TestVerifyCacheExpiryReverifies(t *testing.T) {
	start := time.Now()
	chain := newTestChain(t, "gopher", start.Add(-time.Hour), start.Add(time.Hour))
	cache := NewVerifyCache(16)
	now := start
	cache.now = func() time.Time { return now }

	errExpired := errors.New("x509: certificate has expired or is not yet valid")
	calls := 0
	refuse := false
	verifier := func([][]byte, [][]*x509.Certificate) (error, bool) {
		calls++
		if refuse {
			return errExpired, true
		}
		return nil, true
	}

	require.NoError(t, cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier}))
	require.NoError(t, cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier}))
	assert.Equal(t, 1, calls, "the second call within the window is served")

	// The chain expires; a fresh verification now refuses it.
	now = start.Add(time.Hour + time.Second)
	refuse = true
	err := cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier})
	assert.Same(t, errExpired, err, "an expired chain gets the fresh verifier's error")
	assert.Equal(t, 2, calls, "an expired chain is verified again")

	// And again on every use: an expired decision is never remembered.
	err = cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier})
	assert.Same(t, errExpired, err)
	assert.Equal(t, 3, calls)

	// Before the window (a clock stepped back) is outside it too.
	now = start.Add(-time.Hour - time.Second)
	err = cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier})
	assert.Same(t, errExpired, err)
	assert.Equal(t, 4, calls)
}

// TestVerifyCacheWindowIsTheWholeChain: the window is the intersection of
// every certificate's validity in the verified chain, so an intermediate
// that expires before the leaf ends the remembered decision too.
func TestVerifyCacheWindowIsTheWholeChain(t *testing.T) {
	start := time.Now()
	chain := newTestChain(t, "gopher", start.Add(-time.Hour), start.Add(time.Hour))
	// Shorten the CA's validity to end before the leaf's.
	chain.chains[0][1].NotAfter = start.Add(time.Minute)

	cache := NewVerifyCache(16)
	now := start
	cache.now = func() time.Time { return now }
	calls := 0
	verifier := func([][]byte, [][]*x509.Certificate) (error, bool) {
		calls++
		return nil, true
	}
	require.NoError(t, cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier}))
	require.NoError(t, cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier}))
	assert.Equal(t, 1, calls)
	now = start.Add(2 * time.Minute)
	require.NoError(t, cache.verify(verifyRequest{role: roleServer, rawCerts: chain.raw, verifiedChains: chain.chains, decide: verifier}))
	assert.Equal(t, 2, calls, "the CA's end of validity ends the remembered decision")
}

// TestVerifyCacheDifferentBytesMiss: a chain differing in one byte is a
// different chain, and so is a different verified leaf for the same bytes.
func TestVerifyCacheDifferentBytesMiss(t *testing.T) {
	chain := validChain(t, "gopher")
	cache := NewVerifyCache(16)
	acl := ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)

	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	assertStats(t, cache, 0, 1)

	// Flip the last byte of the leaf (inside its signature): the verifier's
	// rules read the verified leaf, so the decision is the same, but the
	// bytes are not, so it is a miss.
	flipped := append([][]byte(nil), chain.raw...)
	flipped[0] = append([]byte(nil), chain.raw[0]...)
	flipped[0][len(flipped[0])-1] ^= 0x01
	require.NoError(t, acl.VerifyPeerCertificateServer(flipped, chain.chains))
	assertStats(t, cache, 0, 2)

	// The same presented bytes with a different verified leaf is a miss too.
	other := validChain(t, "gopher")
	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, other.chains))
	assertStats(t, cache, 0, 3)

	// Two presented certificates whose concatenation equals one are told
	// apart by the length prefixes.
	split := [][]byte{chain.raw[0][:10], chain.raw[0][10:]}
	require.NoError(t, acl.VerifyPeerCertificateServer(split, chain.chains))
	assertStats(t, cache, 0, 4)

	// And every one of them is now remembered on its own.
	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, chain.chains))
	require.NoError(t, acl.VerifyPeerCertificateServer(flipped, chain.chains))
	require.NoError(t, acl.VerifyPeerCertificateServer(chain.raw, other.chains))
	require.NoError(t, acl.VerifyPeerCertificateServer(split, chain.chains))
	assertStats(t, cache, 4, 4)
}

// TestVerifyCacheConcurrent: 16 goroutines verifying the same and different
// chains, with reloads interleaved, always get the decision the rules make
// for their chain.
func TestVerifyCacheConcurrent(t *testing.T) {
	cache := NewVerifyCache(16)
	acl := ACL{AllowedCNs: []string{"allowed-a", "allowed-b"}}.WithVerifyCache(cache)
	chains := []testChain{
		validChain(t, "allowed-a"),
		validChain(t, "allowed-b"),
		validChain(t, "denied-a"),
		validChain(t, "denied-b"),
	}
	allowed := []bool{true, true, false, false}

	const goroutines, iterations = 16, 250
	var wg sync.WaitGroup
	failures := make(chan string, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				idx := (g + i) % len(chains)
				err := acl.VerifyPeerCertificateServer(chains[idx].raw, chains[idx].chains)
				if (err == nil) != allowed[idx] {
					failures <- fmt.Sprintf("goroutine %d chain %d: got %v", g, idx, err)
					return
				}
				if g == 0 && i%50 == 0 {
					cache.Invalidate()
				}
			}
		}(g)
	}
	wg.Wait()
	close(failures)
	for f := range failures {
		t.Error(f)
	}
	hits, misses := cache.Stats()
	assert.Equal(t, uint64(goroutines*iterations), hits+misses, "every call was either served or verified")
	assert.LessOrEqual(t, cache.Len(), len(chains))
}

// TestVerifyCacheBounded: the cache holds at most its capacity, evicting
// the least recently used decision.
func TestVerifyCacheBounded(t *testing.T) {
	cache := NewVerifyCache(4)
	acl := ACL{AllowAll: true}.WithVerifyCache(cache)
	var chains []testChain
	for i := 0; i < 6; i++ {
		chains = append(chains, validChain(t, fmt.Sprintf("peer-%d", i)))
	}
	for _, c := range chains {
		require.NoError(t, acl.VerifyPeerCertificateServer(c.raw, c.chains))
	}
	assert.Equal(t, 4, cache.Len())
	assertStats(t, cache, 0, 6)

	// The two oldest were evicted; the newest four are still there.
	require.NoError(t, acl.VerifyPeerCertificateServer(chains[0].raw, chains[0].chains))
	assertStats(t, cache, 0, 7)
	require.NoError(t, acl.VerifyPeerCertificateServer(chains[5].raw, chains[5].chains))
	assertStats(t, cache, 1, 7)
	assert.Equal(t, 4, cache.Len())

	assert.Equal(t, DefaultVerifyCacheSize, NewVerifyCache(0).capacity)
}

// TestVerifyCachePolicyConsultingTheClockIsNotRemembered: a policy whose
// decision depends on the clock or the environment is evaluated every time.
func TestVerifyCachePolicyConsultingTheClockIsNotRemembered(t *testing.T) {
	for _, tc := range []struct {
		name   string
		module string
	}{
		{"time.now_ns", `package policy
default allow := false
allow if {
	time.now_ns() > 0
	input.certificate.Subject.CommonName == "gopher"
}
`},
		{"opa.runtime", `package policy
default allow := false
allow if {
	opa.runtime()
	input.certificate.Subject.CommonName == "gopher"
}
`},
		{"nested call", `package policy
default allow := false
allow if {
	count([x | x := time.now_ns()]) > 0
	input.certificate.Subject.CommonName == "gopher"
}
`},
		{"x509 verify", `package policy
default allow := false
allow if {
	not crypto.x509.parse_and_verify_certificates("")
	input.certificate.Subject.CommonName == "gopher"
}
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := validChain(t, "gopher")
			cache := NewVerifyCache(16)
			uncached := ACL{AllowOPAQuery: policy.WrapForTest(prepareQuery(t, tc.module)), OPAQueryTimeout: 10 * time.Second}
			acl := uncached.WithVerifyCache(cache)
			// The decision is whatever the policy makes of the certificate
			// (the x509 builtin errors on its argument, which leaves the rule
			// undefined and the peer refused); the point is that it is made
			// every time and is the same as without the cache.
			want := uncached.VerifyPeerCertificateServer(chain.raw, chain.chains)
			for i := 0; i < 2; i++ {
				got := acl.VerifyPeerCertificateServer(chain.raw, chain.chains)
				if want == nil {
					assert.NoError(t, got)
				} else {
					assert.EqualError(t, got, want.Error())
				}
			}
			assertStats(t, cache, 0, 2)
			assert.Equal(t, 0, cache.Len())
		})
	}
}

// TestVerifyCachePolicyDecisionIsRemembered: a policy that is a function of
// the certificate alone is cached, allow and deny alike.
func TestVerifyCachePolicyDecisionIsRemembered(t *testing.T) {
	cache := NewVerifyCache(16)
	acl := ACL{AllowOPAQuery: policy.WrapForTest(prepareQuery(t, allowGopherPolicy)), OPAQueryTimeout: 10 * time.Second}.WithVerifyCache(cache)
	gopher := validChain(t, "gopher")
	other := validChain(t, "other")
	require.NoError(t, acl.VerifyPeerCertificateServer(gopher.raw, gopher.chains))
	require.Error(t, acl.VerifyPeerCertificateServer(other.raw, other.chains))
	require.NoError(t, acl.VerifyPeerCertificateServer(gopher.raw, gopher.chains))
	require.Error(t, acl.VerifyPeerCertificateServer(other.raw, other.chains))
	assertStats(t, cache, 2, 2)
}

// TestVerifyCachePolicyErrorIsNotRemembered: a policy error is returned
// every time it happens and never from the cache.
func TestVerifyCachePolicyErrorIsNotRemembered(t *testing.T) {
	module := `package policy
default allow := false
allow if {
	to_number(input.certificate.Subject.CommonName) == 1
}
`
	query, err := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(context.Background())
	require.NoError(t, err)
	chain := validChain(t, "gopher")
	cache := NewVerifyCache(16)
	acl := ACL{AllowOPAQuery: policy.WrapForTest(&query), OPAQueryTimeout: 10 * time.Second}.WithVerifyCache(cache)
	for i := 0; i < 2; i++ {
		err := acl.VerifyPeerCertificateServer(chain.raw, chain.chains)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized: policy returned error:")
	}
	assertStats(t, cache, 0, 2)
	assert.Equal(t, 0, cache.Len())
}

// TestVerifyCachePinMode: the pin check is remembered by the presented
// bytes, and an expired pinned certificate, which the pin check accepts, is
// accepted on every use by the check itself, never from the cache.
func TestVerifyCachePinMode(t *testing.T) {
	certDER, digest := makePinTestCert(t)
	cache := NewVerifyCache(16)
	acl := ACL{AllowedPins: []SPKIPin{{hash: crypto.SHA256, digest: digest}}}.WithVerifyCache(cache)
	require.NoError(t, acl.VerifyPeerCertificateServer([][]byte{certDER}, nil))
	require.NoError(t, acl.VerifyPeerCertificateServer([][]byte{certDER}, nil))
	assertStats(t, cache, 1, 1)

	otherDER, _ := makePinTestCert(t)
	require.EqualError(t, acl.VerifyPeerCertificateServer([][]byte{otherDER}, nil), "unauthorized: pin verification failed")
	require.EqualError(t, acl.VerifyPeerCertificateServer([][]byte{otherDER}, nil), "unauthorized: pin verification failed")
	assertStats(t, cache, 2, 2)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-test-expired"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	expiredACL := ACL{AllowedPins: []SPKIPin{spkiPin(t, expiredDER, crypto.SHA256)}}.WithVerifyCache(NewVerifyCache(16))
	require.NoError(t, expiredACL.VerifyPeerCertificateServer([][]byte{expiredDER}, nil))
	require.NoError(t, expiredACL.VerifyPeerCertificateServer([][]byte{expiredDER}, nil))
	assertStats(t, expiredACL.cache, 0, 2)
}

// TestVerifyCacheUnidentifiableInputsBypass: arguments the key cannot
// identify by bytes are verified every time, as the existing verifier tests
// with synthetic chains rely on.
func TestVerifyCacheUnidentifiableInputsBypass(t *testing.T) {
	cache := NewVerifyCache(16)
	acl := ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)
	require.NoError(t, acl.VerifyPeerCertificateServer(nil, fakeChains))
	require.NoError(t, acl.VerifyPeerCertificateServer(nil, fakeChains))
	require.Error(t, acl.VerifyPeerCertificateServer(nil, nil))
	assertStats(t, cache, 0, 3)
	assert.Equal(t, 0, cache.Len())
}

// TestVerifyCacheStoreAfterReloadIsDropped: a decision computed under an
// earlier generation is not stored once a reload has happened in between.
func TestVerifyCacheStoreAfterReloadIsDropped(t *testing.T) {
	chain := validChain(t, "gopher")
	cache := NewVerifyCache(16)
	key, ok := verifyKey(roleServer, chain.raw, chain.chains)
	require.True(t, ok)
	_, generation, hit := cache.lookup(key, time.Now())
	require.False(t, hit)
	cache.Invalidate()
	cache.store(&verifyEntry{key: key, generation: generation, chains: chain.chains, decided: true, notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour)})
	_, _, hit = cache.lookup(key, time.Now())
	assert.False(t, hit, "a decision from before the reload must not survive it")
	assert.Equal(t, 0, cache.Len())
}

// TestWithVerifyCacheBindsOnce: one cache answers for one ACL only.
func TestWithVerifyCacheBindsOnce(t *testing.T) {
	cache := NewVerifyCache(16)
	_ = ACL{AllowAll: true}.WithVerifyCache(cache)
	assert.Panics(t, func() { ACL{AllowedCNs: []string{"x"}}.WithVerifyCache(cache) })
	assert.Panics(t, func() { ACL{}.WithVerifyCache(nil) })
	assert.NotPanics(t, func() { (*VerifyCache)(nil).Invalidate() })
	hits, misses := (*VerifyCache)(nil).Stats()
	assert.Zero(t, hits+misses)
	assert.Zero(t, (*VerifyCache)(nil).Len())
}

// BenchmarkVerifyPeerCertificateServer is the verifier alone, rules and
// policy, with and without the cache: the share of a handshake the cache
// can remove.
func BenchmarkVerifyPeerCertificateServer(b *testing.B) {
	chain := validChain(b, "gopher")
	for _, tc := range []struct {
		name string
		acl  ACL
	}{
		{"rules", ACL{AllowedCNs: []string{"someone", "else", "gopher"}}},
		{"policy", ACL{AllowOPAQuery: policy.WrapForTest(prepareQuery(b, allowGopherPolicy)), OPAQueryTimeout: 10 * time.Second}},
	} {
		b.Run(tc.name+"/uncached", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := tc.acl.VerifyPeerCertificateServer(chain.raw, chain.chains); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(tc.name+"/cached", func(b *testing.B) {
			acl := tc.acl.WithVerifyCache(NewVerifyCache(16))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := acl.VerifyPeerCertificateServer(chain.raw, chain.chains); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
