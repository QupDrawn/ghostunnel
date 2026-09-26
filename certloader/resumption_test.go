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
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	spiffetest "github.com/ghostunnel/ghostunnel/certloader/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticCertificate is a Certificate backed by an in-memory key pair and
// trust store.
type staticCertificate struct {
	cert *tls.Certificate
	pool *x509.CertPool
}

func (s *staticCertificate) Reload() error         { return nil }
func (s *staticCertificate) GetIdentifier() string { return "static" }
func (s *staticCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.cert, nil
}
func (s *staticCertificate) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return s.cert, nil
}
func (s *staticCertificate) GetTrustStore() *x509.CertPool { return s.pool }

// togglePeerVerifier is a VerifyPeerCertificate callback that counts its
// invocations and rejects every peer once denied is set, standing in for an
// access control list whose decision changes after a session was issued.
type togglePeerVerifier struct {
	denied atomic.Bool
	calls  atomic.Int32
}

func (v *togglePeerVerifier) verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	v.calls.Add(1)
	if v.denied.Load() {
		return errors.New("unauthorized: principal not allowed")
	}
	if len(rawCerts) == 0 {
		return errors.New("unauthorized: no certificate presented")
	}
	return nil
}

// handshakeResult is what the server side observed for one connection.
type handshakeResult struct {
	state tls.ConnectionState
	err   error
}

// serveHandshakes accepts connections from listener until it is closed,
// completes the TLS handshake on each and reports the outcome on the returned
// channel. Successful connections get a short payload before being closed, so
// the client can read until EOF and thereby process the TLS 1.3 session
// ticket the server sends after the handshake.
func serveHandshakes(t testing.TB, listener net.Listener) <-chan handshakeResult {
	t.Helper()
	results := make(chan handshakeResult, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			err = tlsConn.Handshake()
			if err == nil {
				_, _ = tlsConn.Write([]byte("ok"))
			}
			results <- handshakeResult{state: tlsConn.ConnectionState(), err: err}
			conn.Close()
		}
	}()
	return results
}

// dialAndDrain dials the server, completes the handshake and reads until the
// server closes the connection. It returns the client-side connection state
// and the first error seen. A TLS 1.3 client finishes its handshake before
// the server has checked the connection, so a server-side refusal surfaces
// as an alert on the first read rather than as a Dial error.
func dialAndDrain(t testing.TB, addr string, config *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadAll(conn)
	return conn.ConnectionState(), err
}

func awaitServerResult(t testing.TB, results <-chan handshakeResult) handshakeResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side handshake result")
		return handshakeResult{}
	}
}

// TestCertSourceResumedSessionIsReverified checks that a session resumed
// from a ticket is re-checked against the server's VerifyPeerCertificate
// callback. Go only invokes that callback on a full handshake, so without a
// resumption check a client whose access has since been withdrawn can keep
// connecting for as long as the ticket keys stay valid.
func TestCertSourceResumedSessionIsReverified(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint16
	}{
		{"TLS1.2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := spiffetest.NewCA(t, spiffeid.RequireTrustDomainFromString("example.org"))
			serverChain, serverKey := ca.CreateX509Certificate(spiffetest.WithIPAddresses(net.IPv4(127, 0, 0, 1)))
			clientChain, clientKey := ca.CreateX509Certificate()
			pool := spiffetest.NewCertPool(ca.X509Authorities())

			serverCert := &tls.Certificate{
				Certificate: [][]byte{serverChain[0].Raw},
				PrivateKey:  serverKey,
			}
			clientCert := tls.Certificate{
				Certificate: [][]byte{clientChain[0].Raw},
				PrivateKey:  clientKey,
			}

			verifier := &togglePeerVerifier{}
			base := &tls.Config{
				ClientAuth:            tls.RequireAndVerifyClientCert,
				VerifyPeerCertificate: verifier.verify,
			}
			source := TLSConfigSourceFromCertificate(&staticCertificate{cert: serverCert, pool: pool}, log.Default())
			serverConfig, err := source.GetServerConfig(base)
			require.NoError(t, err)

			inner, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			listener := NewListener(inner, serverConfig)
			defer listener.Close()
			results := serveHandshakes(t, listener)

			clientConfig := &tls.Config{
				RootCAs:            pool,
				Certificates:       []tls.Certificate{clientCert},
				ClientSessionCache: tls.NewLRUClientSessionCache(1),
				MinVersion:         tc.version,
				MaxVersion:         tc.version,
			}

			// Full handshake: the verifier runs and allows the client.
			state, err := dialAndDrain(t, listener.Addr().String(), clientConfig)
			require.NoError(t, err)
			require.False(t, state.DidResume, "first handshake should be a full handshake")
			require.NoError(t, awaitServerResult(t, results).err)
			require.Equal(t, int32(1), verifier.calls.Load())

			// Resumed handshake while still allowed: resumption itself must
			// keep working.
			state, err = dialAndDrain(t, listener.Addr().String(), clientConfig)
			require.NoError(t, err)
			require.True(t, state.DidResume, "second handshake should resume the session")
			require.NoError(t, awaitServerResult(t, results).err)

			// Withdraw access. The next resumption must be refused.
			verifier.denied.Store(true)
			_, err = dialAndDrain(t, listener.Addr().String(), clientConfig)
			require.Error(t, err, "resumed session must be re-checked by the verifier and refused")
			require.Error(t, awaitServerResult(t, results).err, "server must fail the resumed handshake")

			// The verifier ran on both resumptions, not only on the full handshake.
			assert.Equal(t, int32(3), verifier.calls.Load())
		})
	}
}

// TestSPIFFESourceResumedSessionIsReverified is the same check for the
// Workload API source, whose verifier is layered over the base callback.
func TestSPIFFESourceResumedSessionIsReverified(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(&spiffetest.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  []*x509svid.SVID{svid},
	})
	defer workloadAPI.Stop()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, 10*time.Second, log.Default())
	require.NoError(t, err)
	defer source.(*spiffeTLSConfigSource).Close()

	verifier := &togglePeerVerifier{}
	serverConfig, err := source.GetServerConfig(&tls.Config{VerifyPeerCertificate: verifier.verify})
	require.NoError(t, err)
	clientConfig, err := source.GetClientConfig(&tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(1)})
	require.NoError(t, err)

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	listener := NewListener(inner, serverConfig)
	defer listener.Close()
	results := serveHandshakes(t, listener)

	state, err := dialAndDrain(t, listener.Addr().String(), clientConfig.GetClientConfig())
	require.NoError(t, err)
	require.False(t, state.DidResume)
	require.NoError(t, awaitServerResult(t, results).err)
	require.Equal(t, int32(1), verifier.calls.Load())

	state, err = dialAndDrain(t, listener.Addr().String(), clientConfig.GetClientConfig())
	require.NoError(t, err)
	require.True(t, state.DidResume, "second handshake should resume the session")
	require.NoError(t, awaitServerResult(t, results).err)

	verifier.denied.Store(true)
	_, err = dialAndDrain(t, listener.Addr().String(), clientConfig.GetClientConfig())
	require.Error(t, err, "resumed session must be re-checked by the verifier and refused")
	require.Error(t, awaitServerResult(t, results).err)
	assert.Equal(t, int32(3), verifier.calls.Load())
}

// TestACMEServerConfigReverifiesResumedSessions checks that the ACME builder
// wires the resumption check the same way as the other sources.
func TestACMEServerConfigReverifiesResumedSessions(t *testing.T) {
	magicConfig := certmagic.NewDefault()
	source := &acmeTLSConfigSource{
		magicConfig:  magicConfig,
		gtACMEConfig: &ACMEConfig{},
	}
	verifier := &togglePeerVerifier{}
	acmeConfig := &acmeTLSConfig{
		magicConfig: magicConfig,
		base: &tls.Config{
			ClientAuth:            tls.RequireAndVerifyClientCert,
			VerifyPeerCertificate: verifier.verify,
		},
		source: source,
	}

	tlsConfig := acmeConfig.GetServerConfig()
	require.NotNil(t, tlsConfig.VerifyConnection, "server config must carry a resumption check")

	verifier.denied.Store(true)
	err := tlsConfig.VerifyConnection(tls.ConnectionState{DidResume: true})
	assert.Error(t, err, "a resumed session must be passed through the verifier")
	assert.Equal(t, int32(1), verifier.calls.Load())
}
