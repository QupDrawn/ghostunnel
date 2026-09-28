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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/ghostunnel/ghostunnel/ringtrace"
)

// benchStores lays out a healthy store tree with a fresh super heartbeat,
// as healthyStores does for tests.
func benchStores(b *testing.B) string {
	b.Helper()
	root := b.TempDir()
	for _, m := range []string{"admin", "material", "super", "tunnel"} {
		for _, d := range []string{"heartbeat", "halts"} {
			if err := os.MkdirAll(filepath.Join(root, m, d), 0o755); err != nil {
				b.Fatal(err)
			}
		}
	}
	line := fmt.Sprintf(`{"kind":"heartbeat","version":1,"observer":"super","sequence":42,"timestamp":%q,"cadence_seconds":1,"checks":["member-fresh:tunnel"],"check_count":1,"observed":{"admin":null,"material":null,"tunnel":null},"previous":%s,"boot":null,"stop":false}`+"\n",
		time.Now().UTC().Format("2006-01-02T15:04:05Z"), `"`+strings.Repeat("ab", 32)+`"`)
	if err := os.WriteFile(filepath.Join(root, "super", "heartbeat", "0000000042.hb"), []byte(line), 0o644); err != nil {
		b.Fatal(err)
	}
	return root
}

// benchRing builds a ring by hand: an emitter under SyncEveryLine with the
// real clock, a gate over a healthy tree with a one-hour window under the
// gate state with the ring's window and watch interval and the OS's change
// notification running (as openRing wires it), no verifier (the handshake
// records disable-authentication and an acl line).
func benchRing(b *testing.B) *ring {
	b.Helper()
	cfg := ringtrace.Config{
		Mode: "server", Listen: "127.0.0.1:8443", Target: "127.0.0.1:8080", ProxyProtocol: ringtrace.ProxyProtocolOff,
		ACL: []string{"disable-authentication"}, SandboxState: ringtrace.SandboxUnsupported,
		Material: []ringtrace.Material{{Material: "cert", Path: "/etc/gt/server.crt"}, {Material: "key", Path: "/etc/gt/server.key"}},
		Binary:   testRingBinary,
	}
	goos := "windows"
	cfg.SandboxAccepted = &goos
	emitter, err := ringtrace.Open(b.TempDir(), ringtrace.Options{Config: cfg, PID: 4242, Now: time.Now})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = emitter.Close() })
	gate := ringtrace.NewGate(benchStores(b))
	gate.MaxHeartbeatAge = time.Hour
	state := ringtrace.NewGateState(gate, ringGateWindow, ringWatchInterval)
	if err := state.Watch(); err != nil {
		b.Logf("no change notification on %s: %v (every accept outside the window scans)", runtime.GOOS, err)
	}
	b.Cleanup(state.Close)
	return &ring{emitter: emitter, gate: state, mode: "server", stop: make(chan struct{})}
}

// benchReport adds what the path paid per connection: full gate scans and
// fsyncs (the start line's is included, one in b.N).
func benchReport(b *testing.B, r *ring) {
	b.ReportMetric(float64(r.gate.Scans())/float64(b.N), "scans/op")
	b.ReportMetric(float64(r.emitter.SyncCount())/float64(b.N), "fsync/op")
}

// benchConn is a net.Conn with addresses and nothing else; the ring reads
// only the addresses.
type benchConn struct {
	net.Conn
	local, remote net.Addr
}

func (c benchConn) LocalAddr() net.Addr  { return c.local }
func (c benchConn) RemoteAddr() net.Addr { return c.remote }

// benchOneConnection drives one connection through the observer: accept
// (the gate), handshake (the accept, handshake and acl lines, one fsync)
// and close (the close line, one fsync). It is the proxy's per-connection
// trace cost.
func benchOneConnection(b *testing.B, r *ring, conn net.Conn, state *tls.ConnectionState) {
	obs, err := r.Accepted(conn)
	if err != nil {
		b.Fatal(err)
	}
	obs.Handshake(state, nil)
	obs.Closed(proxy.CloseEOF)
}

func benchConnAndState() (net.Conn, *tls.ConnectionState) {
	conn := benchConn{
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443},
		remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 51234},
	}
	return conn, &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
}

// benchGoroutines is the SetParallelism value that runs n goroutines in
// RunParallel, which multiplies it by GOMAXPROCS.
func benchGoroutines(n int) int {
	if p := runtime.GOMAXPROCS(0); p < n {
		return n / p
	}
	return 1
}

// BenchmarkRingConnPathSerial: one connection at a time.
func BenchmarkRingConnPathSerial(b *testing.B) {
	r := benchRing(b)
	conn, state := benchConnAndState()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchOneConnection(b, r, conn, state)
	}
	benchReport(b, r)
}

// BenchmarkRingConnPathParallel16: sixteen connections in flight; ns/op is
// wall time per connection.
func BenchmarkRingConnPathParallel16(b *testing.B) {
	r := benchRing(b)
	conn, state := benchConnAndState()
	b.SetParallelism(benchGoroutines(16))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchOneConnection(b, r, conn, state)
		}
	})
	benchReport(b, r)
}

// benchChainState is a completed handshake presenting a two-certificate
// chain (a leaf under a CA minted here), the shape a served client leaves
// in tls.ConnectionState.PeerCertificates.
func benchChainState(b *testing.B) *tls.ConnectionState {
	b.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bench-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		b.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		b.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "allowed", OrganizationalUnit: []string{"dev"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames: []string{"allowed.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		b.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	return &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf, caCert}}
}

// BenchmarkRingConnPathVerified: one served connection at a time as the
// tunnel listener records it, a verifier installed and an --allow-cn rule,
// the client's two-certificate chain presented: the rule named from the
// leaf, the chain stored (once; then a stat per connection), the peer
// summarised, the accept, handshake and acl lines written as one batch
// whose commit is waited for in Dialed, then the close line. It is the
// record path of a real connection, without the TLS handshake and the
// dial.
func BenchmarkRingConnPathVerified(b *testing.B) {
	r := benchRing(b)
	r.acl = auth.ACL{AllowedCNs: []string{"allowed"}}
	r.verifier = true
	conn, _ := benchConnAndState()
	state := benchChainState(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		obs, err := r.Accepted(conn)
		if err != nil {
			b.Fatal(err)
		}
		obs.Handshake(state, nil)
		if err := obs.Dialed(nil, nil); err != nil {
			b.Fatal(err)
		}
		obs.Closed(proxy.CloseEOF)
	}
	benchReport(b, r)
}
