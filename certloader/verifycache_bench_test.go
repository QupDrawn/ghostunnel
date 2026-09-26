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
	"crypto/tls"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/policy"
)

// BenchmarkHandshake is one sequential mutually-authenticated handshake
// against an in-process server built from certloader's config, as
// ghostunnel's server mode wires it, in both verify modes: go is the
// config where crypto/tls verifies the client's chain
// (RequireAndVerifyClientCert) and the ACL's verifier is its
// VerifyPeerCertificate callback; acl is the config where the ACL
// verifies the chain itself (GetServerConfigVerifying). full is a new
// session each time (the client keeps no session cache); resumed is a
// session ticket resumption, on which the VerifyConnection hook re-runs
// the verifier. rules is an --allow-cn ACL, policy an OPA policy on the
// common name. Each is measured with and without a VerifyCache bound to
// the ACL; under acl/cached a repeat client skips x509.Verify.
func BenchmarkHandshake(b *testing.B) {
	now := time.Now()
	pki := newTestPKI(b, now.Add(-12*time.Hour), now.Add(12*time.Hour))
	client := pki.clientLeaf(b, "gopher", now.Add(-time.Hour), now.Add(time.Hour))
	for _, mode := range []struct {
		name string
		mode verifyMode
	}{
		{"go", goVerifies},
		{"acl", aclVerifies},
	} {
		for _, acl := range []struct {
			name string
			acl  auth.ACL
		}{
			{"rules", auth.ACL{AllowedCNs: []string{"someone", "else", "gopher"}}},
			{"policy", auth.ACL{AllowOPAQuery: policy.WrapForTest(prepareQuery(b, allowGopherPolicy)), OPAQueryTimeout: 10 * time.Second}},
		} {
			for _, cached := range []struct {
				name string
				bind func(auth.ACL) auth.ACL
			}{
				{"uncached", func(a auth.ACL) auth.ACL { return a }},
				{"cached", func(a auth.ACL) auth.ACL { return a.WithVerifyCache(auth.NewVerifyCache(16)) }},
			} {
				for _, resume := range []struct {
					name   string
					resume bool
				}{
					{"full", false},
					{"resumed", true},
				} {
					b.Run(mode.name+"/"+acl.name+"/"+cached.name+"/"+resume.name, func(b *testing.B) {
						benchmarkHandshake(b, mode.mode, cached.bind(acl.acl), pki, client, resume.resume)
					})
				}
			}
		}
	}
}

func benchmarkHandshake(b *testing.B, mode verifyMode, acl auth.ACL, pki *testPKI, client tls.Certificate, resume bool) {
	f := newChainListener(b, mode, acl, pki)
	addr := f.addr()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := f.listener.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.Handshake(); err == nil {
				_, _ = tlsConn.Write([]byte("ok"))
			}
			conn.Close()
		}
	}()
	config := clientConfig(pki, client, tls.VersionTLS13)
	if resume {
		config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
		// Establish the session to resume, outside the timed loop.
		if _, err := dialAndDrain(b, addr, config); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state, err := dialAndDrain(b, addr, config)
		if err != nil {
			b.Fatal(err)
		}
		if state.DidResume != resume {
			b.Fatalf("resumed = %v, want %v", state.DidResume, resume)
		}
	}
	b.StopTimer()
	f.listener.Close()
	<-done
}
