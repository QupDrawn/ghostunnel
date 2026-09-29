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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/certloader"
	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/ghostunnel/ghostunnel/ringtrace"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caSource is the source for the CA bundle at path and no certificate: the
// source behind a start line that lists no certificate file.
func caSource(t *testing.T, path string) certloader.TLSConfigSource {
	t.Helper()
	cert, err := certloader.NoCertificate(path)
	require.NoError(t, err)
	return certloader.TLSConfigSourceFromCertificate(cert, logger)
}

// swapAfterReload is a source whose Reload is the real one followed by
// swap, which rewrites the files on disk: the window between the load and
// the hashing of what it loaded.
type swapAfterReload struct {
	certloader.TLSConfigSource
	swap func()
}

func (s *swapAfterReload) Reload() error {
	err := s.TLSConfigSource.Reload()
	s.swap()
	return err
}

func (s *swapAfterReload) LoadedFiles() (*certloader.LoadedFiles, bool) {
	return certloader.LoadedFilesOf(s.TLSConfigSource)
}

// materialHash is the recorded hash of the material of the given kind.
func materialHash(t *testing.T, material []ringtrace.Material, kind string) string {
	t.Helper()
	for _, m := range material {
		if m.Material == kind {
			require.NotNil(t, m.SHA256, "%s is recorded with a hash", kind)
			return *m.SHA256
		}
	}
	t.Fatalf("no %s in the material list", kind)
	return ""
}

// rewrite appends to the file at path, which keeps a PEM file what it was
// to the loader and changes its bytes.
func rewrite(t *testing.T, path, suffix string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	data = append(data, suffix...)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	return data
}

// TestRingRecordsTheMaterialAsLoaded: the start line hashes the
// certificate file and the CA bundle as the load read them, and stores
// that bundle, however the files have changed on disk since the load.
func TestRingRecordsTheMaterialAsLoaded(t *testing.T) {
	pki := newRingPKI(t)
	env := newRingEnv(t, pki, t.TempDir(), healthyStores(t), 10*time.Second)
	cert, err := os.ReadFile(pki.certPath)
	require.NoError(t, err)
	ca, err := os.ReadFile(pki.caPath)
	require.NoError(t, err)

	// Swapped after the load, before the start line is built.
	rewrite(t, pki.certPath, "\n")
	rewrite(t, pki.caPath, "\n")

	cfg, gotCA, err := ringConfig("server", "a", "b", proxy.ProxyProtocolOff, nil, ringtrace.SandboxApplied, ringSources{tls: env.tlsConfigSource}, ringRules{acl: auth.ACL{AllowAll: true}})
	require.NoError(t, err)
	assert.Equal(t, ringtrace.MaterialHash(cert), materialHash(t, cfg.Material, "cert"), "the certificate is recorded as loaded")
	assert.Equal(t, ringtrace.MaterialHash(ca), materialHash(t, cfg.Material, "ca"), "the CA bundle is recorded as loaded")
	assert.Equal(t, ca, gotCA, "the bundle stored is the bundle loaded")
}

// TestRingRecordsTheReloadAsLoaded: a reload line hashes the files as the
// reload read them, and stores that bundle, even when they are rewritten
// between the reload and the hashing.
func TestRingRecordsTheReloadAsLoaded(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
	source := &swapAfterReload{TLSConfigSource: env.tlsConfigSource, swap: func() {}}
	cfg, ca, err := ringConfig("server", "a", "b", proxy.ProxyProtocolOff, nil, sandboxState(), ringSources{tls: source}, ringRules{acl: auth.ACL{AllowAll: true}})
	require.NoError(t, err)
	r, err := openRing(cfg, ca, auth.ACL{AllowAll: true}, true, ringSources{tls: source})
	require.NoError(t, err)
	defer r.close()

	// The reload loads the rotated files; the swap rewrites them again
	// before the reload is recorded.
	cert := rewrite(t, pki.certPath, "\n")
	bundle := rewrite(t, pki.caPath, "\n")
	source.swap = func() {
		rewrite(t, pki.certPath, "\n")
		rewrite(t, pki.caPath, "\n")
	}
	require.True(t, r.reloaded(source.Reload()))

	reloads := reloadRecords(t, traces)
	require.Len(t, reloads, 1)
	assert.Equal(t, "ok", reloads[0].Outcome)
	assert.Equal(t, ringtrace.MaterialHash(cert), materialHash(t, reloads[0].Material, "cert"), "the certificate is recorded as reloaded")
	assert.Equal(t, ringtrace.MaterialHash(bundle), materialHash(t, reloads[0].Material, "ca"), "the CA bundle is recorded as reloaded")
	stored, err := ringtrace.ReadMaterial(traces, ringtrace.MaterialHash(bundle))
	require.NoError(t, err, "the bundle reloaded is stored under its hash")
	assert.Equal(t, bundle, stored)
}

// TestRingFailedReloadRecordsTheMaterialStillLoaded: a reload that fails
// leaves the material of the last load in use, and that is what its line
// records, not the file that could not be loaded.
func TestRingFailedReloadRecordsTheMaterialStillLoaded(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
	cert, err := os.ReadFile(pki.certPath)
	require.NoError(t, err)
	cfg, ca, err := ringConfig("server", "a", "b", proxy.ProxyProtocolOff, nil, sandboxState(), ringSources{tls: env.tlsConfigSource}, ringRules{acl: auth.ACL{AllowAll: true}})
	require.NoError(t, err)
	r, err := openRing(cfg, ca, auth.ACL{AllowAll: true}, true, ringSources{tls: env.tlsConfigSource})
	require.NoError(t, err)
	defer r.close()

	require.NoError(t, os.WriteFile(pki.certPath, []byte("not a certificate"), 0o644))
	assert.False(t, r.reloaded(env.tlsConfigSource.Reload()))

	reloads := reloadRecords(t, traces)
	require.Len(t, reloads, 1)
	assert.Equal(t, "failed", reloads[0].Outcome)
	assert.False(t, reloads[0].Serving)
	assert.Equal(t, ringtrace.MaterialHash(cert), materialHash(t, reloads[0].Material, "cert"), "the certificate still loaded is recorded")
}

// TestRingMaterialOnlyFromTheConfiguredFiles: a source whose load did not
// read the configured file, or no source at all, is an error, and the
// entry carries no hash: the process does not start (or the reload fails)
// on material it cannot say it loaded.
func TestRingMaterialOnlyFromTheConfiguredFiles(t *testing.T) {
	pki := newRingPKI(t)
	saved := saveRingFlags()
	t.Cleanup(saved)
	*certPath, *keyPath, *caBundlePath = "", "", pki.caPath

	other := filepath.Join(t.TempDir(), "other-ca.pem")
	data, err := os.ReadFile(pki.caPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(other, data, 0o644))

	material, ca, err := ringMaterial(ringSources{tls: caSource(t, other)})
	assert.ErrorContains(t, err, "did not load "+pki.caPath)
	assert.Nil(t, ca)
	for _, m := range material {
		if m.Material == "ca" {
			assert.Nil(t, m.SHA256, "no hash for a bundle the source did not load")
		}
	}

	_, _, err = ringMaterial(ringSources{tls: nil})
	assert.ErrorContains(t, err, "no TLS configuration source")

	material, ca, err = ringMaterial(ringSources{tls: caSource(t, pki.caPath)})
	require.NoError(t, err)
	assert.Equal(t, data, ca)
	assert.Equal(t, ringtrace.MaterialHash(data), materialHash(t, material, "ca"))
}

// ringPolicyV0 allows the peer whose certificate's common name is
// "allowed", through a rule that also reads its own annotation: a Rego v0
// module that decides otherwise when parsed any other way.
const ringPolicyV0 = `
package policy
import input

default allow := false

# METADATA
# title: allow the allowed
allow {
    input.certificate.Subject.CommonName == "allowed"
    rego.metadata.rule().title == "allow the allowed"
}
`

// memberCompile compiles the policy bytes a member reads under the hash
// the trace records, as the members compile them
// (observers/*/substance.go, policy): a .rego file is a Rego v0 module
// parsed with annotations processed, given as a parsed module.
func memberCompile(t *testing.T, path, query string, data []byte) *rego.PreparedEvalQuery {
	t.Helper()
	mod, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{RegoVersion: ast.RegoV0, ProcessAnnotation: true})
	require.NoError(t, err)
	pq, err := rego.New(rego.Query(query), rego.ParsedModule(mod), rego.SetRegoVersion(ast.RegoV0)).PrepareForEval(context.Background())
	require.NoError(t, err)
	return &pq
}

// proxyAllows is the tunnel ACL's decision on the peer under the policy,
// the verifier's own callback.
func proxyAllows(t *testing.T, pki *ringPKI, pol auth.ACL, peer tls.Certificate) bool {
	t.Helper()
	return pol.VerifyPeerCertificateServerFor(pki.pool, time.Now)(peer.Certificate, nil) == nil
}

// memberAllows is the member's decision on the peer: the query on the
// input {"certificate": leaf}, as auth evaluates it.
func memberAllows(t *testing.T, pq *rego.PreparedEvalQuery, peer tls.Certificate) bool {
	t.Helper()
	leaf, err := x509.ParseCertificate(peer.Certificate[0])
	require.NoError(t, err)
	rs, err := pq.Eval(context.Background(), rego.EvalInput(map[string]any{"certificate": leaf}))
	require.NoError(t, err)
	return rs.Allowed()
}

// TestRingRecordsThePolicyAsCompiled: the start line and a reload line
// hash the policy as the load read the bytes it compiled, however the file
// changed on disk since; and the proxy's decision under that policy is the
// decision a member reaches compiling the bytes the hash names afresh.
func TestRingRecordsThePolicyAsCompiled(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
	query := "data.policy.allow"
	path := filepath.Join(t.TempDir(), "policy.rego")
	first := []byte(ringPolicyV0)
	require.NoError(t, os.WriteFile(path, first, 0o644))
	pol, err := loadOPAPolicy(path, query)
	require.NoError(t, err)
	acl := auth.ACL{AllowOPAQuery: pol, OPAQueryTimeout: 10 * time.Second}

	// Swapped after the load, before the start line is built.
	require.NoError(t, os.WriteFile(path, []byte("package policy\ndefault allow := true\n"), 0o644))
	sources := ringSources{tls: env.tlsConfigSource, policy: pol, policyPath: path}
	cfg, ca, err := ringConfig("server", "a", "b", proxy.ProxyProtocolOff, nil, sandboxState(), sources, ringRules{acl: acl})
	require.NoError(t, err)
	recorded := materialHash(t, cfg.Material, "policy")
	assert.Equal(t, ringtrace.MaterialHash(first), recorded, "the policy is recorded as compiled")

	member := memberCompile(t, path, query, first)
	for _, peer := range []tls.Certificate{pki.allowed, pki.denied} {
		assert.Equal(t, proxyAllows(t, pki, acl, peer), memberAllows(t, member, peer), "the proxy and a fresh compile of the recorded bytes agree")
	}
	require.True(t, proxyAllows(t, pki, acl, pki.allowed))
	require.False(t, proxyAllows(t, pki, acl, pki.denied))

	r, err := openRing(cfg, ca, acl, true, sources)
	require.NoError(t, err)
	defer r.close()

	// The reload compiles the rotated file; it is rewritten again before
	// the reload is recorded.
	second := []byte(ringPolicyV0 + "\n# rotated\n")
	require.NoError(t, os.WriteFile(path, second, 0o644))
	require.NoError(t, pol.Reload())
	require.NoError(t, os.WriteFile(path, []byte("package policy\ndefault allow := true\n"), 0o644))
	require.True(t, r.reloaded(nil))
	reloads := reloadRecords(t, traces)
	require.Len(t, reloads, 1)
	assert.Equal(t, ringtrace.MaterialHash(second), materialHash(t, reloads[0].Material, "policy"), "the policy is recorded as reloaded")
	member = memberCompile(t, path, query, second)
	for _, peer := range []tls.Certificate{pki.allowed, pki.denied} {
		assert.Equal(t, proxyAllows(t, pki, acl, peer), memberAllows(t, member, peer), "the proxy and a fresh compile of the reloaded bytes agree")
	}
}

// TestRingPolicyOnlyFromThePolicyLoaded: a policy path with no policy
// loaded from it (none at all, one with no file, one loaded from another
// path) is an error and the entry carries no hash.
func TestRingPolicyOnlyFromThePolicyLoaded(t *testing.T) {
	pki := newRingPKI(t)
	saved := saveRingFlags()
	t.Cleanup(saved)
	*certPath, *keyPath, *caBundlePath = "", "", pki.caPath
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.rego")
	other := filepath.Join(dir, "other.rego")
	for _, p := range []string{path, other} {
		require.NoError(t, os.WriteFile(p, []byte(ringPolicyV0), 0o644))
	}
	fromOther, err := loadOPAPolicy(other, "data.policy.allow")
	require.NoError(t, err)
	noFile := policy.WrapForTest(memberCompile(t, path, "data.policy.allow", []byte(ringPolicyV0)))

	for name, pol := range map[string]policy.Policy{"none": nil, "another path": fromOther, "no file": noFile} {
		sources := ringSources{tls: caSource(t, pki.caPath), policy: pol, policyPath: path}
		material, _, err := ringMaterial(sources)
		assert.ErrorContains(t, err, "no policy was loaded from "+path, name)
		for _, m := range material {
			if m.Material == "policy" {
				assert.Nil(t, m.SHA256, "%s: no hash for a policy not loaded from the path", name)
			}
		}
	}
}
