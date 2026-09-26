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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuer is a CA certificate with its key, for issuing test chains.
type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64 = 100

// newIssuer issues a CA certificate signed by parent (self-signed when
// parent is nil), valid over the given window.
func newIssuer(t testing.TB, name string, parent *issuer, notBefore, notAfter time.Time) *issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial++
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	parentCert, parentKey := template, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &issuer{cert: cert, key: key}
}

// newLeaf issues a leaf with the given common name, validity and extended
// key usages from parent.
func newLeaf(t testing.TB, cn string, parent *issuer, notBefore, notAfter time.Time, eku ...x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial++
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func rawOf(certs ...*x509.Certificate) [][]byte {
	raw := make([][]byte, len(certs))
	for i, cert := range certs {
		raw[i] = cert.Raw
	}
	return raw
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// chainCase is one presented chain against one trust store, with what a
// verification under crypto/tls's options is expected to make of it.
type chainCase struct {
	name     string
	rawCerts [][]byte
	roots    *x509.CertPool
	// wantChain is the expected verified chain (leaf first, root last), nil
	// when the chain must not verify.
	wantChain []*x509.Certificate
	// wantReason is the expected CertificateInvalidError reason, when the
	// error is of that type; wantUnknownCA when it is UnknownAuthorityError.
	wantReason    x509.InvalidReason
	wantUnknownCA bool
}

// chainMatrix is the matrix of chains the differential tests run: valid,
// expired leaf, not-yet-valid leaf, unknown CA, missing intermediate, wrong
// EKU, two intermediates, expired intermediate.
func chainMatrix(t testing.TB, now time.Time) []chainCase {
	t.Helper()
	root := newIssuer(t, "root", nil, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	inter := newIssuer(t, "intermediate", root, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	inter2 := newIssuer(t, "intermediate 2", inter, now.Add(-6*time.Hour), now.Add(6*time.Hour))
	shortInter := newIssuer(t, "short intermediate", root, now.Add(-2*time.Hour), now.Add(-time.Hour))
	other := newIssuer(t, "other root", nil, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	roots := poolOf(root.cert)

	valid := newLeaf(t, "gopher", inter, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	expired := newLeaf(t, "gopher", inter, now.Add(-2*time.Hour), now.Add(-time.Hour), x509.ExtKeyUsageClientAuth)
	future := newLeaf(t, "gopher", inter, now.Add(time.Hour), now.Add(2*time.Hour), x509.ExtKeyUsageClientAuth)
	foreign := newLeaf(t, "gopher", other, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	serverOnly := newLeaf(t, "gopher", inter, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageServerAuth)
	deep := newLeaf(t, "gopher", inter2, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	underShort := newLeaf(t, "gopher", shortInter, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)

	return []chainCase{
		{name: "valid", rawCerts: rawOf(valid, inter.cert), roots: roots, wantChain: []*x509.Certificate{valid, inter.cert, root.cert}},
		{name: "expired leaf", rawCerts: rawOf(expired, inter.cert), roots: roots, wantReason: x509.Expired},
		{name: "not yet valid", rawCerts: rawOf(future, inter.cert), roots: roots, wantReason: x509.Expired},
		{name: "unknown CA", rawCerts: rawOf(foreign, other.cert), roots: roots, wantUnknownCA: true},
		{name: "missing intermediate", rawCerts: rawOf(valid), roots: roots, wantUnknownCA: true},
		{name: "wrong EKU", rawCerts: rawOf(serverOnly, inter.cert), roots: roots, wantReason: x509.IncompatibleUsage},
		{name: "two intermediates", rawCerts: rawOf(deep, inter2.cert, inter.cert), roots: roots, wantChain: []*x509.Certificate{deep, inter2.cert, inter.cert, root.cert}},
		{name: "expired intermediate", rawCerts: rawOf(underShort, shortInter.cert), roots: roots, wantReason: x509.Expired},
	}
}

// goVerify is, line for line, what crypto/tls does with a client's
// certificates under RequireAndVerifyClientCert
// (GOROOT/src/crypto/tls/handshake_server.go, processCertsFromClient).
func goVerify(t testing.TB, rawCerts [][]byte, roots *x509.CertPool, now time.Time) ([][]*x509.Certificate, error) {
	t.Helper()
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		require.NoError(t, err)
		certs[i] = cert
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   now,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	return certs[0].Verify(opts)
}

func assertSameChains(t *testing.T, want, got [][]*x509.Certificate) {
	t.Helper()
	require.Equal(t, len(want), len(got), "number of chains")
	for i := range want {
		require.Equal(t, len(want[i]), len(got[i]), "length of chain %d", i)
		for j := range want[i] {
			assert.Equal(t, want[i][j].Raw, got[i][j].Raw, "chain %d certificate %d", i, j)
		}
	}
}

// TestClientChainVerifierMatchesCryptoTLS: for every chain in the matrix,
// the ACL's chain verification returns the same chains, byte for byte,
// and the same error class as x509.Verify called the way crypto/tls calls
// it, wrapped in the same *tls.CertificateVerificationError with the same
// wording.
func TestClientChainVerifierMatchesCryptoTLS(t *testing.T) {
	now := time.Now()
	for _, tc := range chainMatrix(t, now) {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &clientChainVerifier{roots: tc.roots, now: func() time.Time { return now }}
			want, wantErr := goVerify(t, tc.rawCerts, tc.roots, now)
			got, gotErr, cacheable := verifier.verify(tc.rawCerts)

			if tc.wantChain != nil {
				require.NoError(t, wantErr, "the matrix expects this chain to verify")
				require.NoError(t, gotErr)
				assertSameChains(t, [][]*x509.Certificate{tc.wantChain}, want)
				assertSameChains(t, want, got)
				assert.True(t, cacheable)
				return
			}
			require.Error(t, wantErr, "the matrix expects this chain not to verify")
			require.Error(t, gotErr)
			assert.Nil(t, got)
			var verification *tls.CertificateVerificationError
			require.ErrorAs(t, gotErr, &verification, "the error crypto/tls returns")
			assert.Equal(t, len(tc.rawCerts), len(verification.UnverifiedCertificates))
			assert.Equal(t, wantErr.Error(), verification.Err.Error(), "the exact x509 error")
			assert.IsType(t, wantErr, verification.Err)
			wrapped := &tls.CertificateVerificationError{Err: wantErr}
			assert.Equal(t, wrapped.Error(), gotErr.Error(), "the wording a log or the ring records")
			if tc.wantUnknownCA {
				var unknown x509.UnknownAuthorityError
				assert.ErrorAs(t, gotErr, &unknown)
				assert.ErrorAs(t, wantErr, &unknown)
			} else {
				var invalid x509.CertificateInvalidError
				require.ErrorAs(t, gotErr, &invalid)
				assert.Equal(t, tc.wantReason, invalid.Reason)
				require.ErrorAs(t, wantErr, &invalid)
				assert.Equal(t, tc.wantReason, invalid.Reason)
			}
		})
	}
}

// TestClientChainVerifierUsesTheConfigClock: the clock the binding was
// given is the one the verification uses, not the wall clock: a chain
// valid now is refused as expired on a clock a day ahead and as not yet
// valid on one a day behind.
func TestClientChainVerifierUsesTheConfigClock(t *testing.T) {
	now := time.Now()
	valid := chainMatrix(t, now)[0]
	for _, tc := range []struct {
		name  string
		clock time.Time
		ok    bool
	}{
		{"now", now, true},
		{"a day ahead", now.Add(24 * time.Hour), false},
		{"a day behind", now.Add(-24 * time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acl := ACL{AllowedCNs: []string{"gopher"}}
			verify := acl.VerifyPeerCertificateServerFor(valid.roots, func() time.Time { return tc.clock })
			err := verify(valid.rawCerts, nil)
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			var invalid x509.CertificateInvalidError
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, x509.Expired, invalid.Reason)
		})
	}
}

// TestClientChainVerifierRulesRunOnTheBuiltChain: the rules see the chain
// the ACL built, exactly as they see one crypto/tls built: the leaf's
// common name decides, and a chain that does not verify never reaches
// them (an allow-all ACL still refuses it).
func TestClientChainVerifierRulesRunOnTheBuiltChain(t *testing.T) {
	now := time.Now()
	matrix := chainMatrix(t, now)
	clock := func() time.Time { return now }
	allowed := ACL{AllowedCNs: []string{"gopher"}}.VerifyPeerCertificateServerFor(matrix[0].roots, clock)
	refused := ACL{AllowedCNs: []string{"someone-else"}}.VerifyPeerCertificateServerFor(matrix[0].roots, clock)
	allowAll := ACL{AllowAll: true}.VerifyPeerCertificateServerFor(matrix[0].roots, clock)
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantChain != nil {
				assert.NoError(t, allowed(tc.rawCerts, nil))
				assert.EqualError(t, refused(tc.rawCerts, nil), "unauthorized: invalid principal, or principal not allowed")
				assert.NoError(t, allowAll(tc.rawCerts, nil))
				return
			}
			var verification *tls.CertificateVerificationError
			assert.ErrorAs(t, allowed(tc.rawCerts, nil), &verification)
			assert.ErrorAs(t, refused(tc.rawCerts, nil), &verification)
			assert.ErrorAs(t, allowAll(tc.rawCerts, nil), &verification)
		})
	}
	// The pin check does not verify the chain, bound or not.
	pinned := ACL{AllowedPins: []SPKIPin{spkiPin(t, matrix[3].rawCerts[0], crypto.SHA256)}}.VerifyPeerCertificateServerFor(matrix[0].roots, clock)
	assert.NoError(t, pinned(matrix[3].rawCerts, nil), "an unknown-CA chain passes by its pin")
	assert.EqualError(t, pinned(matrix[0].rawCerts, nil), "unauthorized: pin verification failed")
	// The callback ignores what crypto/tls hands it as verified chains
	// (nothing under RequireAnyClientCert): the chain it built decides.
	root := newIssuer(t, "another root", nil, now.Add(-time.Hour), now.Add(time.Hour))
	nobody := newLeaf(t, "nobody", root, now.Add(-time.Hour), now.Add(time.Hour))
	gopher := newLeaf(t, "gopher", root, now.Add(-time.Hour), now.Add(time.Hour))
	assert.NoError(t, allowed(matrix[0].rawCerts, [][]*x509.Certificate{{nobody, root.cert}}))
	assert.Error(t, refused(matrix[0].rawCerts, [][]*x509.Certificate{{gopher, root.cert}}))
}

// TestVerifyCacheRemembersChainVerification: with a cache bound, the
// same bytes that verified are verified once and served after, while a
// chain that did not verify is refused afresh on every use, with the same
// error each time; VerifiedChainsFor returns the chains of a chain that
// verified and nothing for one that did not; a reload makes the verifier
// decide again.
func TestVerifyCacheRemembersChainVerification(t *testing.T) {
	now := time.Now()
	matrix := chainMatrix(t, now)
	cache := NewVerifyCache(16)
	acl := ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)
	verify := acl.VerifyPeerCertificateServerFor(matrix[0].roots, func() time.Time { return now })

	var hits, misses uint64
	remembered := 0
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			first := verify(tc.rawCerts, nil)
			second := verify(tc.rawCerts, nil)
			chains, ok := acl.VerifiedChainsFor(tc.rawCerts)
			if tc.wantChain != nil {
				assert.NoError(t, first)
				assert.NoError(t, second)
				require.True(t, ok, "a verified chain is remembered")
				assertSameChains(t, [][]*x509.Certificate{tc.wantChain}, chains)
				misses, hits = misses+1, hits+1
				remembered++
			} else {
				require.Error(t, first)
				require.Error(t, second)
				assert.NotSame(t, first, second, "a refusal is made afresh")
				assert.Equal(t, first.Error(), second.Error())
				assert.False(t, ok, "a chain that did not verify has no verified chains")
				assert.Nil(t, chains)
				misses += 2
			}
			assertStats(t, cache, hits, misses)
		})
	}
	assert.Equal(t, remembered, cache.Len())

	cache.Invalidate()
	_, ok := acl.VerifiedChainsFor(matrix[0].rawCerts)
	assert.False(t, ok, "a reload forgets the chains")
	require.NoError(t, verify(matrix[0].rawCerts, nil))
	assertStats(t, cache, hits, misses+1)
	_, ok = acl.VerifiedChainsFor(matrix[0].rawCerts)
	assert.True(t, ok)

	// An unbound ACL, or one whose cache was never told of these bytes,
	// has no chains to report.
	_, ok = ACL{AllowedCNs: []string{"gopher"}}.VerifiedChainsFor(matrix[0].rawCerts)
	assert.False(t, ok)
	_, ok = acl.VerifiedChainsFor(nil)
	assert.False(t, ok)
}

// TestVerifyCacheChainWindowUsesTheConfigClock: the remembered chain
// verification is served only while the config's clock is inside the
// chain's validity window (the intersection over the whole chain); once
// the clock leaves it, x509.Verify runs again and refuses. The cache's own
// wall clock is not what decides, so a server whose config clock differs
// from the wall clock (or a test that moves it) gets the same answer
// crypto/tls would give on that clock.
func TestVerifyCacheChainWindowUsesTheConfigClock(t *testing.T) {
	start := time.Now()
	matrix := chainMatrix(t, start)
	// "two intermediates": inter2 expires 6h after start, the leaf 1h after.
	deep := matrix[6]
	now := start
	cache := NewVerifyCache(16)
	cache.now = func() time.Time { return start } // the wall clock stands still
	acl := ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)
	verify := acl.VerifyPeerCertificateServerFor(deep.roots, func() time.Time { return now })

	require.NoError(t, verify(deep.rawCerts, nil))
	require.NoError(t, verify(deep.rawCerts, nil))
	assertStats(t, cache, 1, 1)

	// The leaf expires on the config clock: not served, verified again,
	// refused as expired, and refused again on every use.
	now = start.Add(time.Hour + time.Second)
	for i := 0; i < 2; i++ {
		err := verify(deep.rawCerts, nil)
		var invalid x509.CertificateInvalidError
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, x509.Expired, invalid.Reason)
	}
	assertStats(t, cache, 1, 3)
	_, ok := acl.VerifiedChainsFor(deep.rawCerts)
	assert.False(t, ok, "an expired chain's verification is not what is remembered")

	// Back inside the window the chain verifies again, and is remembered.
	now = start
	require.NoError(t, verify(deep.rawCerts, nil))
	require.NoError(t, verify(deep.rawCerts, nil))
	assertStats(t, cache, 2, 4)

	// The window is the whole chain's: the leaf is still valid when the
	// second intermediate has expired, and the verification says so.
	root := newIssuer(t, "root", nil, start.Add(-24*time.Hour), start.Add(24*time.Hour))
	short := newIssuer(t, "short", root, start.Add(-time.Hour), start.Add(10*time.Minute))
	leaf := newLeaf(t, "gopher", short, start.Add(-time.Hour), start.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	raw, roots := rawOf(leaf, short.cert), poolOf(root.cert)
	verify = acl.VerifyPeerCertificateServerFor(roots, func() time.Time { return now })
	require.NoError(t, verify(raw, nil))
	require.NoError(t, verify(raw, nil))
	assertStats(t, cache, 3, 5)
	now = start.Add(30 * time.Minute)
	err := verify(raw, nil)
	var invalid x509.CertificateInvalidError
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, x509.Expired, invalid.Reason)
	assertStats(t, cache, 3, 6)
}

// TestVerifyCacheChainIsRememberedWhenTheDecisionIsNot: a policy that
// consults the clock is evaluated on every use, while the chain
// verification under it is remembered: the second use serves the chains
// and runs the policy.
func TestVerifyCacheChainIsRememberedWhenTheDecisionIsNot(t *testing.T) {
	now := time.Now()
	valid := chainMatrix(t, now)[0]
	module := `package policy
default allow := false
allow if {
	time.now_ns() > 0
	input.certificate.Subject.CommonName == "gopher"
}
`
	cache := NewVerifyCache(16)
	acl := ACL{AllowOPAQuery: policy.WrapForTest(prepareQuery(t, module)), OPAQueryTimeout: 10 * time.Second}.WithVerifyCache(cache)
	verify := acl.VerifyPeerCertificateServerFor(valid.roots, func() time.Time { return now })
	require.NoError(t, verify(valid.rawCerts, nil))
	require.NoError(t, verify(valid.rawCerts, nil))
	assertStats(t, cache, 1, 1)
	require.Equal(t, 1, cache.Len())
	key, ok := verifyKey(roleServer, valid.rawCerts, nil)
	require.True(t, ok)
	entry, _, hit := cache.lookup(key, now)
	require.True(t, hit)
	assert.False(t, entry.decided, "the policy's decision is not remembered")
	assert.NotNil(t, entry.chains, "the chain verification is")
	chains, ok := acl.VerifiedChainsFor(valid.rawCerts)
	require.True(t, ok)
	assertSameChains(t, [][]*x509.Certificate{valid.wantChain}, chains)

	// A policy that is a function of the certificate is remembered whole.
	cache2 := NewVerifyCache(16)
	acl2 := ACL{AllowOPAQuery: policy.WrapForTest(prepareQuery(t, allowGopherPolicy)), OPAQueryTimeout: 10 * time.Second}.WithVerifyCache(cache2)
	verify2 := acl2.VerifyPeerCertificateServerFor(valid.roots, func() time.Time { return now })
	require.NoError(t, verify2(valid.rawCerts, nil))
	require.NoError(t, verify2(valid.rawCerts, nil))
	entry, _, hit = cache2.lookup(key, now)
	require.True(t, hit)
	assert.True(t, entry.decided)
}

// TestVerifiedChainsForCryptoTLSChains: a chain crypto/tls (or go-spiffe)
// built and handed to the plain callback is reported by VerifiedChainsFor
// too, under the presented bytes.
func TestVerifiedChainsForCryptoTLSChains(t *testing.T) {
	now := time.Now()
	valid := chainMatrix(t, now)[0]
	goChains, err := goVerify(t, valid.rawCerts, valid.roots, now)
	require.NoError(t, err)
	cache := NewVerifyCache(16)
	acl := ACL{AllowedCNs: []string{"gopher"}}.WithVerifyCache(cache)
	_, ok := acl.VerifiedChainsFor(valid.rawCerts)
	assert.False(t, ok)
	require.NoError(t, acl.VerifyPeerCertificateServer(valid.rawCerts, goChains))
	chains, ok := acl.VerifiedChainsFor(valid.rawCerts)
	require.True(t, ok)
	assertSameChains(t, goChains, chains)
	// A refused decision on a verified chain still reports the chain: the
	// chain verified; the rules refused.
	refusing := ACL{AllowedCNs: []string{"nobody"}}.WithVerifyCache(NewVerifyCache(16))
	require.Error(t, refusing.VerifyPeerCertificateServer(valid.rawCerts, goChains))
	chains, ok = refusing.VerifiedChainsFor(valid.rawCerts)
	require.True(t, ok)
	assertSameChains(t, goChains, chains)
}

// TestClientChainVerifierLiveRootsAreNotRemembered: on the platforms
// where crypto/x509 hands a system root pool to the platform verifier, a
// verification against such a pool is never remembered; a pool from a
// bundle is remembered everywhere.
func TestClientChainVerifierLiveRootsAreNotRemembered(t *testing.T) {
	now := time.Now()
	valid := chainMatrix(t, now)[0]
	assert.False(t, rootsVerifiedLive(valid.roots), "a bundle pool is verified by crypto/x509 itself")
	live := runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios"
	assert.Equal(t, live, rootsVerifiedLive(nil))
	system, err := x509.SystemCertPool()
	if err == nil {
		assert.Equal(t, live, rootsVerifiedLive(system))
	}
	if !live {
		t.Skip("the platform verifier is not used on " + runtime.GOOS)
	}
	cache := NewVerifyCache(16)
	acl := ACL{AllowAll: true}.WithVerifyCache(cache)
	verify := acl.VerifyPeerCertificateServerFor(nil, func() time.Time { return now })
	for i := 0; i < 2; i++ {
		err := verify(valid.rawCerts, nil)
		var verification *tls.CertificateVerificationError
		require.ErrorAs(t, err, &verification, "a private root is unknown to the platform")
	}
	assertStats(t, cache, 0, 2)
	assert.Equal(t, 0, cache.Len(), "nothing verified live is remembered")
}

// TestClientChainVerifierRefusesWhatCryptoTLSRefusesFirst: the two
// conditions crypto/tls refuses before calling the callback are refused
// here too, fail closed, and not remembered.
func TestClientChainVerifierRefusesWhatCryptoTLSRefusesFirst(t *testing.T) {
	now := time.Now()
	cache := NewVerifyCache(16)
	acl := ACL{AllowAll: true}.WithVerifyCache(cache)
	verify := acl.VerifyPeerCertificateServerFor(x509.NewCertPool(), func() time.Time { return now })
	assert.EqualError(t, verify(nil, nil), "tls: client didn't provide a certificate")
	err := verify([][]byte{{0x30, 0x00}}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls: failed to parse client certificate")
	assert.Equal(t, 0, cache.Len())
}

// BenchmarkVerifyClientChain is the server verifier alone on a chain with
// one intermediate, verifying the chain itself (x509.Verify, two ECDSA
// P-256 signature checks, then the rules), with and without the cache: the
// share of a handshake a repeat client skips on a hit. go is the same
// rules on a chain crypto/tls built, for the cost of the rules alone.
func BenchmarkVerifyClientChain(b *testing.B) {
	now := time.Now()
	valid := chainMatrix(b, now)[0]
	goChains, err := goVerify(b, valid.rawCerts, valid.roots, now)
	require.NoError(b, err)
	clock := func() time.Time { return now }
	acl := ACL{AllowedCNs: []string{"someone", "else", "gopher"}}
	b.Run("go/uncached", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := acl.VerifyPeerCertificateServer(valid.rawCerts, goChains); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("acl/uncached", func(b *testing.B) {
		verify := acl.VerifyPeerCertificateServerFor(valid.roots, clock)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := verify(valid.rawCerts, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("acl/cached", func(b *testing.B) {
		verify := acl.WithVerifyCache(NewVerifyCache(16)).VerifyPeerCertificateServerFor(valid.roots, clock)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := verify(valid.rawCerts, nil); err != nil {
				b.Fatal(err)
			}
		}
	})
}
