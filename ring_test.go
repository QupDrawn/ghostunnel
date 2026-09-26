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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/ghostunnel/ghostunnel/ringtrace"
	"github.com/ghostunnel/ghostunnel/wildcard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ringPKI is a throwaway CA with a server certificate for 127.0.0.1 and two
// client certificates, one the ACL allows and one it does not.
type ringPKI struct {
	caPath, certPath, keyPath string
	pool                      *x509.CertPool
	allowed, denied           tls.Certificate
}

func newRingPKI(t *testing.T) *ringPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ring-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, ips []net.IP) (tls.Certificate, []byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		return pair, certPEM, keyPEM
	}
	_, serverPEM, serverKeyPEM := issue(2, "ring-test-server", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1)})
	allowed, _, _ := issue(3, "allowed", x509.ExtKeyUsageClientAuth, nil)
	denied, _, _ := issue(4, "denied", x509.ExtKeyUsageClientAuth, nil)

	p := &ringPKI{
		caPath:   filepath.Join(dir, "ca.pem"),
		certPath: filepath.Join(dir, "server.crt"),
		keyPath:  filepath.Join(dir, "server.key"),
		pool:     pool, allowed: allowed, denied: denied,
	}
	require.NoError(t, os.WriteFile(p.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644))
	require.NoError(t, os.WriteFile(p.certPath, serverPEM, 0o644))
	require.NoError(t, os.WriteFile(p.keyPath, serverKeyPEM, 0o600))
	return p
}

// ringServer is a server-mode ghostunnel run in-process through serverListen
// against an echo backend.
type ringServer struct {
	env      *Environment
	addr     string
	log      *bytes.Buffer
	logs     *sync.Mutex
	done     chan error
	stopOnce sync.Once
}

func (s *ringServer) logged() string {
	s.logs.Lock()
	defer s.logs.Unlock()
	return s.log.String()
}

// stop shuts the server down through the shutdown channel and waits; a
// second call returns at once.
func (s *ringServer) stop(t *testing.T) {
	t.Helper()
	s.stopOnce.Do(func() {
		select {
		case s.env.shutdownChannel <- true:
		default:
		}
		select {
		case err := <-s.done:
			assert.NoError(t, err)
		case <-time.After(30 * time.Second):
			t.Fatal("serverListen did not return after shutdown")
		}
	})
}

// lockedBuffer is a bytes.Buffer safe for the logger and the test to share.
type lockedBuffer struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (b lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// freePort reserves and releases a loopback port for the server to bind.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	l.Close()
	return addr
}

// newRingEnv sets the server flags for an --allow-cn allowed run with the
// given ring flags, an echo backend as target and the logger captured, and
// builds the Environment serverListen takes.
func newRingEnv(t *testing.T, pki *ringPKI, traces, stores string, maxAge time.Duration) *Environment {
	t.Helper()
	return newRingEnvOn(t, pki, traces, stores, maxAge, echoBackend(t))
}

// echoBackend is a loopback listener that echoes every connection.
func echoBackend(t *testing.T) net.Listener {
	t.Helper()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return backend
}

// newRingEnvOn is newRingEnv against the given backend listener, which the
// test serves itself when it wants to see what the backend sees.
func newRingEnvOn(t *testing.T, pki *ringPKI, traces, stores string, maxAge time.Duration, backend net.Listener) *Environment {
	t.Helper()

	saved := saveRingFlags()
	t.Cleanup(saved)
	*serverListenAddress = freePort(t)
	*serverForwardAddress = backend.Addr().String()
	*serverAllowAll = false
	*serverAllowedCNs = []string{"allowed"}
	*certPath = pki.certPath
	*keyPath = pki.keyPath
	*caBundlePath = pki.caPath
	*ringTraces = traces
	*ringStores = stores
	*ringHeartbeatMaxAge = maxAge

	origLogger := logger
	logger = log.New(lockedBuffer{&sync.Mutex{}, &bytes.Buffer{}}, "", 0)
	t.Cleanup(func() { logger = origLogger })

	source, err := getTLSConfigSource(false)
	require.NoError(t, err)
	dial, err := serverBackendDialer()
	require.NoError(t, err)
	return &Environment{
		status:          newStatusHandler(dial, "server", *serverListenAddress, *serverForwardAddress, ""),
		shutdownChannel: make(chan bool, 1),
		shutdownTimeout: time.Hour,
		dial:            dial,
		proxyMetrics:    proxy.NilMetrics(),
		tlsConfigSource: source,
	}
}

// startRingServer starts serverListen on newRingEnv and waits until it
// accepts.
func startRingServer(t *testing.T, pki *ringPKI, traces, stores string, maxAge time.Duration) *ringServer {
	t.Helper()
	return startRingServerWith(t, pki, traces, stores, maxAge, nil)
}

// startRingServerWith is startRingServer with a hook that adjusts the flags
// after newRingEnv set the baseline and before serverListen reads them.
func startRingServerWith(t *testing.T, pki *ringPKI, traces, stores string, maxAge time.Duration, configure func()) *ringServer {
	t.Helper()
	return startRingServerOn(t, pki, traces, stores, maxAge, echoBackend(t), configure)
}

// startRingServerOn is startRingServerWith against the given backend
// listener.
func startRingServerOn(t *testing.T, pki *ringPKI, traces, stores string, maxAge time.Duration, backend net.Listener, configure func()) *ringServer {
	t.Helper()
	env := newRingEnvOn(t, pki, traces, stores, maxAge, backend)
	if configure != nil {
		configure()
	}
	sink := logger.Writer().(lockedBuffer)
	s := &ringServer{env: env, addr: *serverListenAddress, log: sink.buf, logs: sink.mu, done: make(chan error, 1)}
	go func() { s.done <- serverListen(env, nil) }()

	// Wait for the accept loop, not by connecting (a probe connection would
	// itself be traced) but on the status handler's own readiness flag,
	// which serverListen sets once the listener is bound and accepting.
	deadline := time.Now().Add(10 * time.Second)
	for {
		env.status.mu.Lock()
		listening := env.status.listening
		env.status.mu.Unlock()
		if listening {
			break
		}
		select {
		case err := <-s.done:
			t.Fatalf("serverListen returned early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never started listening")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() { s.stop(t) })
	return s
}

// saveRingFlags snapshots every flag the ring tests touch and returns the
// function that restores them.
func saveRingFlags() func() {
	var (
		listen, target, cert, key, ca = *serverListenAddress, *serverForwardAddress, *certPath, *keyPath, *caBundlePath
		allowAll, cns                 = *serverAllowAll, *serverAllowedCNs
		traces, stores, maxAge        = *ringTraces, *ringStores, *ringHeartbeatMaxAge
		tick                          = *ringTick
		keystore, workload, acme      = *keystorePath, *useWorkloadAPI, *serverAutoACMEFQDN
		lifetime, closeT              = *maxConnLifetime, *closeTimeout
		pins, disableAuth             = *serverAllowSpkiPin, *serverDisableAuth
		policyPath, query             = *serverAllowPolicy, *serverAllowQuery
		status, unsafe                = *statusAddress, *serverUnsafeTarget
		ciphers, maxTLS, alpnFlag     = *enabledCipherSuites, *maxTLSVersion, *alpn
		proxyProto, proxyMode         = *serverProxyProtocol, *serverProxyProtocolMode
		quietFlags, connect           = *quiet, *connectTimeout
		accepted, outcome             = *acceptNoSandbox, sandboxOutcome
		hostnameOnly                  = *clientVerifyHostnameOnly
	)
	var disabled bool
	if disableLandlock != nil {
		disabled = *disableLandlock
	}
	// Flags are not parsed in tests, so the defaults validateFlags and the
	// proxy rely on are set here.
	decideTestSandbox()
	*connectTimeout = 10 * time.Second
	*ringTick = 5 * time.Second
	*keystorePath, *useWorkloadAPI, *serverAutoACMEFQDN = "", false, ""
	*maxConnLifetime, *closeTimeout = 0, time.Second
	*serverAllowSpkiPin, *serverDisableAuth = nil, false
	*serverAllowPolicy, *serverAllowQuery = "", ""
	*statusAddress, *serverUnsafeTarget = "", false
	*enabledCipherSuites, *maxTLSVersion, *alpn = "AES,CHACHA", "", ""
	*serverProxyProtocol, *serverProxyProtocolMode = false, ""
	*quiet = nil
	decodedServerPins = nil
	// The client validators run on this baseline too, with no --verify-*
	// rule, so hostname-only verification is accepted explicitly here.
	*clientVerifyHostnameOnly = true
	return func() {
		*serverListenAddress, *serverForwardAddress, *certPath, *keyPath, *caBundlePath = listen, target, cert, key, ca
		*serverAllowAll, *serverAllowedCNs = allowAll, cns
		*ringTraces, *ringStores, *ringHeartbeatMaxAge = traces, stores, maxAge
		*ringTick = tick
		*keystorePath, *useWorkloadAPI, *serverAutoACMEFQDN = keystore, workload, acme
		*maxConnLifetime, *closeTimeout = lifetime, closeT
		*serverAllowSpkiPin, *serverDisableAuth = pins, disableAuth
		*serverAllowPolicy, *serverAllowQuery = policyPath, query
		*statusAddress, *serverUnsafeTarget = status, unsafe
		*enabledCipherSuites, *maxTLSVersion, *alpn = ciphers, maxTLS, alpnFlag
		*serverProxyProtocol, *serverProxyProtocolMode = proxyProto, proxyMode
		*quiet, *connectTimeout = quietFlags, connect
		*acceptNoSandbox, sandboxOutcome = accepted, outcome
		*clientVerifyHostnameOnly = hostnameOnly
		if disableLandlock != nil {
			*disableLandlock = disabled
		}
	}
}

// decideTestSandbox settles the process sandbox for a test the way run does,
// without sandboxing the test process: on Linux the state is set to applied
// directly, since a state other than applied refuses to start there and
// running landlock would confine the test process; on a build with no
// sandbox facility the attempt is made (it decides unsupported) and the
// absence is accepted by naming this OS, which is the only way ghostunnel
// starts there. The rule itself is never weakened; a test that wants the
// refusal clears the acceptance or changes the state after this ran.
func decideTestSandbox() {
	*acceptNoSandbox = ""
	if runtime.GOOS == "linux" {
		sandboxOutcome = ringtrace.SandboxApplied
		return
	}
	*acceptNoSandbox = runtime.GOOS
	sandboxOutcome = setupSandbox(false)
}

// TestSandboxAcceptanceRule: the rule that decides whether ghostunnel may
// start, given --accept-no-sandbox, the OS it runs on and the process
// sandbox's state, over every combination. A build with no sandbox
// facility (state unsupported) starts only under an acceptance naming its
// own OS exactly; an acceptance is refused wherever a sandbox facility
// exists, whatever that sandbox's state, so it becomes invalid the moment a
// platform gains one; and a state that has not been decided is refused.
func TestSandboxAcceptanceRule(t *testing.T) {
	const (
		ok        = ""
		undecided = "undecided"
		rule1     = "has no process sandbox"
		rule2     = "does not name this OS"
		rule3     = "has a process sandbox"
		rule4     = "serves only sandboxed"
	)
	check := func(flag, goos, state, want string) {
		t.Helper()
		err := validateSandboxAcceptance(flag, goos, state)
		if want == ok {
			assert.NoError(t, err, "flag=%q goos=%s state=%q", flag, goos, state)
			return
		}
		require.Error(t, err, "flag=%q goos=%s state=%q", flag, goos, state)
		assert.Contains(t, err.Error(), want, "flag=%q goos=%s state=%q", flag, goos, state)
	}

	// The headline cases, spelled out.
	check("", "windows", ringtrace.SandboxUnsupported, rule1)
	check("windows", "windows", ringtrace.SandboxUnsupported, ok)
	check("linux", "windows", ringtrace.SandboxUnsupported, rule2)
	check("Windows", "windows", ringtrace.SandboxUnsupported, rule2)
	check("windows", "linux", ringtrace.SandboxApplied, rule3)
	check("linux", "linux", ringtrace.SandboxApplied, rule3)
	check("linux", "linux", ringtrace.SandboxFailed, rule3)
	check("linux", "linux", ringtrace.SandboxDisabled, rule3)
	check("linux", "linux", ringtrace.SandboxSkipped, rule3)
	check("", "linux", ringtrace.SandboxApplied, ok)
	// A sandbox facility that exists but did not restrict the process is
	// refused: this build serves only sandboxed, or on a platform with no
	// facility explicitly accepted. --disable-landlock and PKCS#11 are
	// therefore unusable.
	check("", "linux", ringtrace.SandboxFailed, rule4)
	check("", "linux", ringtrace.SandboxDisabled, rule4)
	check("", "linux", ringtrace.SandboxSkipped, rule4)
	check("", "linux", "", undecided)
	check("linux", "linux", "", undecided)
	err := validateSandboxAcceptance("", "windows", ringtrace.SandboxUnsupported)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--accept-no-sandbox=windows", "the message names the value that would be accepted")
	for _, state := range []string{ringtrace.SandboxFailed, ringtrace.SandboxDisabled, ringtrace.SandboxSkipped} {
		err := validateSandboxAcceptance("", "linux", state)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state "+state, "the message names the state")
	}

	// Every combination: unset and every OS name as the flag, three OSes,
	// every state and the undecided one.
	states := append([]string{""}, ringtrace.SandboxStates...)
	oses := []string{"linux", "windows", "darwin"}
	flags := append([]string{""}, oses...)
	n := 0
	for _, goos := range oses {
		for _, state := range states {
			for _, flag := range flags {
				var want string
				switch {
				case state == "":
					want = undecided
				case flag == "" && state == ringtrace.SandboxUnsupported:
					want = rule1
				case flag == "" && state != ringtrace.SandboxApplied:
					want = rule4
				case flag == "":
					want = ok
				case state != ringtrace.SandboxUnsupported:
					want = rule3
				case flag != goos:
					want = rule2
				default:
					want = ok
				}
				check(flag, goos, state, want)
				n++
			}
		}
	}
	assert.Equal(t, 3*6*4, n)
}

// TestSandboxAcceptanceWiring: the rule is wired where the ring flags are
// validated (serverValidateFlags, clientValidateFlags, and run before
// anything else happens) and again in openRing before any listener binds,
// against the state setupSandbox decided on this host; the start line
// carries that state and the acceptance. On a host with no sandbox facility
// (this Windows host) the server does not start without
// --accept-no-sandbox=<GOOS>, starts with it, and refuses an acceptance
// naming another OS; on Linux an acceptance is refused outright.
func TestSandboxAcceptanceWiring(t *testing.T) {
	flag := app.GetFlag("accept-no-sandbox")
	require.NotNil(t, flag, "--accept-no-sandbox is a flag on every build")
	assert.Empty(t, flag.Model().Default, "no default: the acceptance is always explicit")
	pki := newRingPKI(t)

	const (
		rule1 = "this build has no process sandbox; pass --accept-no-sandbox="
		rule2 = "does not name this OS"
		rule3 = "has a process sandbox"
	)

	// validators sets a configuration both validators accept, as
	// TestRingFlagValidation does, with the sandbox decided by the baseline.
	validators := func(t *testing.T) {
		t.Helper()
		t.Cleanup(saveRingFlags())
		dir := t.TempDir()
		*certPath, *keyPath = "cert", "key"
		*serverAllowAll, *serverAllowedCNs = true, nil
		*serverForwardAddress = "127.0.0.1:8080"
		origClientListen, origClientTarget := *clientListenAddress, *clientForwardAddress
		t.Cleanup(func() { *clientListenAddress, *clientForwardAddress = origClientListen, origClientTarget })
		*clientListenAddress, *clientForwardAddress = "127.0.0.1:8081", "127.0.0.1:8443"
		*ringTraces, *ringStores, *ringHeartbeatMaxAge, *ringTick = dir, dir, 5*time.Second, time.Second
		require.NoError(t, serverValidateFlags(), "the baseline is accepted")
		require.NoError(t, clientValidateFlags(), "the baseline is accepted")
	}
	refusedByBoth := func(t *testing.T, want string) {
		t.Helper()
		for name, validate := range map[string]func() error{"server": serverValidateFlags, "client": clientValidateFlags} {
			err := validate()
			require.Error(t, err, name)
			assert.Contains(t, err.Error(), want, name)
		}
	}
	neverBinds := func(t *testing.T, env *Environment, traces, want string) {
		t.Helper()
		err := serverListen(env, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), want)
		_, dialErr := net.DialTimeout("tcp", *serverListenAddress, time.Second)
		assert.Error(t, dialErr, "the listener never bound")
		entries, err := os.ReadDir(traces)
		require.NoError(t, err)
		assert.Empty(t, entries, "refused before the trace was opened: no boot was written")
	}

	t.Run("an undecided state is refused everywhere", func(t *testing.T) {
		validators(t)
		sandboxOutcome = ""
		refusedByBoth(t, "undecided")
		env := newRingEnv(t, pki, t.TempDir(), healthyStores(t), 10*time.Second)
		sandboxOutcome = ""
		err := serverListen(env, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "undecided")
	})

	if runtime.GOOS == "linux" {
		t.Run("the state on this host is decided by the attempt", func(t *testing.T) {
			t.Cleanup(saveRingFlags())
			assert.Equal(t, ringtrace.SandboxApplied, sandboxState(), "the test baseline pins the state applied without running landlock")
			assert.Equal(t, ringtrace.SandboxSkipped, setupSandbox(true), "PKCS#11 skips landlock")
			*disableLandlock = true
			assert.Equal(t, ringtrace.SandboxDisabled, setupSandbox(false), "--disable-landlock turns the attempt off")
		})
		t.Run("without an acceptance the validators pass and the start line carries the state", func(t *testing.T) {
			validators(t)
			assert.Equal(t, "", *acceptNoSandbox)
			traces := t.TempDir()
			s := startRingServer(t, pki, traces, healthyStores(t), 10*time.Second)
			got, err := echoThrough(s.addr, pki, pki.allowed)
			require.NoError(t, err)
			assert.Equal(t, "ping", got)
			cfg := records(t, traces, 1)[0].Body.(*ringtrace.Start).Config
			assert.Equal(t, ringtrace.SandboxApplied, cfg.SandboxState)
			assert.Nil(t, cfg.SandboxAccepted)
		})
		t.Run("a sandbox that did not restrict the process refuses to start", func(t *testing.T) {
			for _, state := range []string{ringtrace.SandboxDisabled, ringtrace.SandboxFailed, ringtrace.SandboxSkipped} {
				validators(t)
				sandboxOutcome = state
				refusedByBoth(t, "serves only sandboxed")
				traces := t.TempDir()
				env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
				sandboxOutcome = state
				neverBinds(t, env, traces, "state "+state+" is refused")
			}
		})
		t.Run("an acceptance is refused: this build has a sandbox facility", func(t *testing.T) {
			validators(t)
			*acceptNoSandbox = "linux"
			refusedByBoth(t, rule3)
			traces := t.TempDir()
			env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
			*acceptNoSandbox = "linux"
			neverBinds(t, env, traces, rule3)
		})
		return
	}

	// This host has no sandbox facility.
	t.Run("the state on this host is unsupported", func(t *testing.T) {
		t.Cleanup(saveRingFlags())
		assert.Equal(t, ringtrace.SandboxUnsupported, sandboxState())
		assert.Equal(t, ringtrace.SandboxUnsupported, setupSandbox(false))
		assert.Equal(t, ringtrace.SandboxUnsupported, setupSandbox(true), "there is no facility for PKCS#11 to skip")
	})

	t.Run("without the acceptance the validators refuse", func(t *testing.T) {
		validators(t)
		*acceptNoSandbox = ""
		refusedByBoth(t, rule1+runtime.GOOS)
		*acceptNoSandbox = "linux"
		refusedByBoth(t, rule2)
	})

	t.Run("without the acceptance the server refuses to start and never binds", func(t *testing.T) {
		traces := t.TempDir()
		env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
		*acceptNoSandbox = ""
		neverBinds(t, env, traces, rule1+runtime.GOOS+" to run without one")
	})

	t.Run("an acceptance naming another OS is refused", func(t *testing.T) {
		for _, other := range []string{"linux", "darwin", strings.ToUpper(runtime.GOOS[:1]) + runtime.GOOS[1:]} {
			traces := t.TempDir()
			env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
			*acceptNoSandbox = other
			neverBinds(t, env, traces, rule2)
		}
	})

	t.Run("with --accept-no-sandbox=<GOOS> it starts and the start line records it", func(t *testing.T) {
		traces := t.TempDir()
		s := startRingServer(t, pki, traces, healthyStores(t), 10*time.Second)
		require.Equal(t, runtime.GOOS, *acceptNoSandbox, "the baseline names this OS")
		got, err := echoThrough(s.addr, pki, pki.allowed)
		require.NoError(t, err)
		assert.Equal(t, "ping", got)
		cfg := records(t, traces, 1)[0].Body.(*ringtrace.Start).Config
		assert.Equal(t, ringtrace.SandboxUnsupported, cfg.SandboxState)
		require.NotNil(t, cfg.SandboxAccepted)
		assert.Equal(t, runtime.GOOS, *cfg.SandboxAccepted)

		var raw []byte
		require.NoError(t, filepath.WalkDir(traces, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, ".trace") {
				raw, err = ringtrace.ReadSegmentContent(path)
			}
			return err
		}))
		assert.Contains(t, string(raw), `"sandbox_state":"unsupported","sandbox_accepted":"`+runtime.GOOS+`"`)
		assert.NotContains(t, string(raw), `"landlock"`)
	})

	t.Run("run refuses before anything else happens", func(t *testing.T) {
		t.Cleanup(saveRingFlags())
		origClientListen, origClientTarget, origClientDisableAuth := *clientListenAddress, *clientForwardAddress, *clientDisableAuth
		t.Cleanup(func() {
			*clientListenAddress, *clientForwardAddress, *clientDisableAuth = origClientListen, origClientTarget, origClientDisableAuth
		})
		// kingpin leaves a flag absent from the command line at its current
		// value, so the credentials other tests set are cleared: this run's
		// are the keystore below and nothing else.
		*certPath, *keyPath, *caBundlePath = "", "", ""
		*serverAllowedCNs, *clientDisableAuth = nil, false
		common := []string{"--keystore", "keystore.p12", "--ring-heartbeat-max-age", "1s", "--ring-tick", "100ms", "--ring-traces", t.TempDir(), "--ring-stores", t.TempDir()}
		server := append([]string{"server", "--listen", freePort(t), "--target", "127.0.0.1:1", "--allow-all"}, common...)
		client := append([]string{"client", "--listen", freePort(t), "--target", "127.0.0.1:1", "--verify-hostname-only"}, common...)
		for name, args := range map[string][]string{"server": server, "client": client} {
			// kingpin leaves a flag absent from the command line at its
			// current value, so the acceptance the baseline set is cleared
			// first: this run gives none.
			*acceptNoSandbox = ""
			err := run(args)
			require.Error(t, err, name)
			assert.Contains(t, err.Error(), rule1+runtime.GOOS, name)
			err = run(append(append([]string{}, args...), "--accept-no-sandbox=linux"))
			require.Error(t, err, name)
			assert.Contains(t, err.Error(), rule2, name)
		}
	})
}

// echoThrough connects with the given client certificate, sends a payload
// and returns what came back, or the error. A refusal by the server surfaces
// on the first read under TLS 1.3.
func echoThrough(addr string, pki *ringPKI, cert tls.Certificate) (string, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pki.pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		return "", err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// records reads the trace and returns every record of the single boot,
// waiting until a close for the given number of connections has landed.
func records(t *testing.T, traces string, closes int) []ringtrace.Record {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		trace, err := ringtrace.Read(traces)
		require.NoError(t, err)
		require.Len(t, trace.Boots, 1)
		recs := trace.Boots[0].Records
		n := 0
		for _, r := range recs {
			if r.Body.Kind() == ringtrace.KindClose {
				n++
			}
		}
		if n >= closes {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d close records, trace holds %d", closes, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// kinds lists the kinds of the records, leaving out the ticks, which land
// on their own clock among everything else.
func kinds(recs []ringtrace.Record) string {
	var out []string
	for _, r := range recs {
		if r.Body.Kind() == ringtrace.KindTick {
			continue
		}
		out = append(out, string(r.Body.Kind()))
	}
	return strings.Join(out, " ")
}

func statusCode(env *Environment) int {
	rec := httptest.NewRecorder()
	env.statusMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_status", nil))
	return rec.Code
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestRingIsMandatory: there is no flag combination that runs ghostunnel
// without its observer ring. --ring-traces and --ring-stores default to the
// ring's standard tree and an empty value is refused; --ring-heartbeat-max-age
// has no default and is required; a trace root that cannot be opened
// refuses to start; and a store tree that is absent, or that holds no
// coordinator heartbeat, refuses every connection (cold start) until the
// coordinator's heartbeat is fresh, with the reason logged, a close with
// reason halt in the trace and /_status answering 503.
func TestRingIsMandatory(t *testing.T) {
	// The baked defaults are the observers' standard tree.
	assert.Equal(t, []string{"/var/lib/ghostunnel-ring/stores/gt"}, app.GetFlag("ring-traces").Model().Default)
	assert.Equal(t, []string{"/var/lib/ghostunnel-ring/stores"}, app.GetFlag("ring-stores").Model().Default)
	assert.Empty(t, app.GetFlag("ring-heartbeat-max-age").Model().Default, "the heartbeat window has no default")
	for _, name := range []string{"disable-ring", "no-ring", "ring-optional", "unsafe-no-ring"} {
		assert.Nil(t, app.GetFlag(name), "no flag turns the ring off: %s", name)
	}

	pki := newRingPKI(t)

	t.Run("trace root that cannot be opened refuses to start", func(t *testing.T) {
		env := newRingEnv(t, pki, filepath.Join(t.TempDir(), "absent"), healthyStores(t), 10*time.Second)
		err := serverListen(env, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ringtrace")
		_, dialErr := net.DialTimeout("tcp", *serverListenAddress, time.Second)
		assert.Error(t, dialErr, "the listener never bound")
	})

	t.Run("absent store tree refuses every connection", func(t *testing.T) {
		traces := t.TempDir()
		s := startRingServer(t, pki, traces, filepath.Join(t.TempDir(), "absent"), 10*time.Second)
		_, err := echoThrough(s.addr, pki, pki.allowed)
		assert.Error(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
		assert.Contains(t, s.logged(), "refusing connection")
		assert.Contains(t, s.logged(), "gate: root")
		recs := records(t, traces, 1)
		assert.Equal(t, "start accept close", kinds(recs))
		assert.Equal(t, "halt", recs[2].Body.(*ringtrace.Close).Reason)
	})

	t.Run("cold start: no coordinator heartbeat refuses until one is fresh", func(t *testing.T) {
		traces := t.TempDir()
		stores := healthyStores(t)
		require.NoError(t, os.Remove(filepath.Join(stores, "super", "heartbeat", "0000000042.hb")))
		s := startRingServer(t, pki, traces, stores, 10*time.Second)
		require.NotNil(t, s.env.ring)
		require.NotNil(t, s.env.ring.emitter, "the emitter is always open")
		require.NotNil(t, s.env.ring.gate, "the gate is always consulted")
		require.NotNil(t, s.env.status.refusal)

		_, err := echoThrough(s.addr, pki, pki.allowed)
		assert.Error(t, err, "nothing is served before the coordinator is alive")
		assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
		assert.Contains(t, s.logged(), "holds no heartbeat")

		writeSuperHeartbeat(t, stores, 1)
		got, err := echoThrough(s.addr, pki, pki.allowed)
		require.NoError(t, err, "a fresh heartbeat lets the proxying start, without a restart")
		assert.Equal(t, "ping", got)
		assert.Equal(t, http.StatusOK, statusCode(s.env))
		recs := records(t, traces, 2)
		assert.Equal(t, "start accept close accept handshake acl close", kinds(recs))
		assert.Equal(t, "halt", recs[2].Body.(*ringtrace.Close).Reason)
	})
}

// TestRingFlagValidation: the ring flags cannot be emptied and the heartbeat
// window must be given explicitly, in server and client mode alike.
func TestRingFlagValidation(t *testing.T) {
	restore := saveRingFlags()
	defer restore()
	dir := t.TempDir()
	*certPath, *keyPath = "cert", "key"
	*serverAllowAll, *serverAllowedCNs = true, nil
	*serverForwardAddress = "127.0.0.1:8080"
	origClientListen, origClientTarget := *clientListenAddress, *clientForwardAddress
	defer func() { *clientListenAddress, *clientForwardAddress = origClientListen, origClientTarget }()
	*clientListenAddress, *clientForwardAddress = "127.0.0.1:8081", "127.0.0.1:8443"

	*ringTraces, *ringStores, *ringHeartbeatMaxAge, *ringTick = dir, dir, 5*time.Second, time.Second
	assert.NoError(t, validateRingFlags(), "roots and an explicit window are valid")
	assert.NoError(t, serverValidateFlags())
	assert.NoError(t, clientValidateFlags())

	*ringHeartbeatMaxAge = 0
	assert.Error(t, validateRingFlags(), "--ring-heartbeat-max-age is required")
	assert.Error(t, serverValidateFlags(), "server mode refuses to start without the window")
	assert.Error(t, clientValidateFlags(), "client mode refuses to start without the window")

	*ringHeartbeatMaxAge = -time.Second
	assert.Error(t, validateRingFlags(), "a negative window is refused")

	*ringHeartbeatMaxAge = 5 * time.Second
	*ringTick = 0
	assert.Error(t, validateRingFlags(), "--ring-tick must be above zero: the trace's heartbeat cannot be turned off")
	*ringTick = 5 * time.Second
	assert.Error(t, validateRingFlags(), "a tick at or above the heartbeat window cannot be fresh")
	*ringTick = time.Second
	assert.NoError(t, validateRingFlags())
	*ringStores = ""
	assert.Error(t, validateRingFlags(), "an empty --ring-stores does not turn the gate off")

	*ringStores, *ringTraces = dir, ""
	assert.Error(t, validateRingFlags(), "an empty --ring-traces does not turn the trace off")
}

// TestRingTraceOfServedAndDeniedConnections: the trace holds start, then
// accept, handshake (verified), acl allow and close for a served
// connection, and handshake refused, acl deny and close refused for a peer
// the ACL does not allow; the start line describes the configuration.
func TestRingTraceOfServedAndDeniedConnections(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	s := startRingServer(t, pki, traces, healthyStores(t), 10*time.Second)

	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)
	_, err = echoThrough(s.addr, pki, pki.denied)
	assert.Error(t, err, "a peer outside the allow list is refused")

	recs := records(t, traces, 2)
	assert.Equal(t, "start accept handshake acl close accept handshake acl close", kinds(recs))

	start := recs[0].Body.(*ringtrace.Start)
	assert.Equal(t, int64(1), start.Boot)
	assert.Equal(t, int64(os.Getpid()), start.PID)
	cfg := start.Config
	assert.Equal(t, "server", cfg.Mode)
	assert.Equal(t, *serverListenAddress, cfg.Listen)
	assert.Equal(t, *serverForwardAddress, cfg.Target)
	assert.Nil(t, cfg.StatusListen)
	assert.False(t, cfg.StatusClientCert, "the status listener verifies a certificate only if given")
	assert.True(t, cfg.PprofCmdlineRedacted)
	assert.True(t, cfg.ShutdownRequiresClientCert)
	assert.True(t, cfg.SessionTickets)
	assert.True(t, cfg.VerifyOnResume, "the resumed-session re-verification hook is installed")
	assert.Equal(t, []string{"allow-cn:allowed"}, cfg.ACL, "the rule in force, in the closed vocabulary")
	assert.Equal(t, int64(0), cfg.LifetimeCapSeconds, "no cap configured, none invented")
	assert.Equal(t, sandboxState(), cfg.SandboxState, "the state decided at startup, as recorded")
	if runtime.GOOS == "linux" {
		assert.Equal(t, ringtrace.SandboxApplied, cfg.SandboxState, "the only state that serves where a facility exists")
		assert.Nil(t, cfg.SandboxAccepted)
	} else {
		assert.Equal(t, ringtrace.SandboxUnsupported, cfg.SandboxState)
		require.NotNil(t, cfg.SandboxAccepted)
		assert.Equal(t, runtime.GOOS, *cfg.SandboxAccepted)
	}
	certHash, caHash := fileSHA256(t, pki.certPath), fileSHA256(t, pki.caPath)
	assert.Equal(t, []ringtrace.Material{
		{Material: "cert", Path: pki.certPath, SHA256: &certHash},
		{Material: "key", Path: pki.keyPath, SHA256: nil},
		{Material: "ca", Path: pki.caPath, SHA256: &caHash},
	}, cfg.Material)

	accept := recs[1].Body.(*ringtrace.Accept)
	assert.Equal(t, int64(1), accept.Conn)
	assert.Equal(t, s.addr, accept.Listener)
	assert.True(t, strings.HasPrefix(accept.Remote, "127.0.0.1:"))

	hs := recs[2].Body.(*ringtrace.Handshake)
	assert.Equal(t, int64(1), hs.Conn)
	assert.Equal(t, "ok", hs.Outcome)
	assert.False(t, hs.Resumed)
	assert.True(t, hs.Verified)
	assert.Equal(t, "TLS 1.3", hs.Protocol)
	require.NotNil(t, hs.Peer)
	assert.Equal(t, "CN=allowed", hs.Peer.Subject)
	assert.Equal(t, "CN=ring-test-ca", hs.Peer.Issuer)
	assert.Equal(t, "3", hs.Peer.Serial)
	assert.Equal(t, []string{}, hs.Peer.SANs)
	leaf := sha256.Sum256(pki.allowed.Certificate[0])
	assert.Equal(t, hex.EncodeToString(leaf[:]), hs.Peer.Fingerprint)
	assert.Nil(t, hs.Error)

	acl := recs[3].Body.(*ringtrace.ACL)
	assert.Equal(t, ringtrace.ACL{Conn: 1, Decision: "allow", Rule: "allow-cn", Reason: "allowed by --allow-cn"}, *acl)

	closed := recs[4].Body.(*ringtrace.Close)
	assert.Equal(t, int64(1), closed.Conn)
	assert.Equal(t, "eof", closed.Reason)
	assert.GreaterOrEqual(t, closed.DurationMS, int64(0))
	assert.Less(t, closed.DurationMS, int64(10000))

	hs2 := recs[6].Body.(*ringtrace.Handshake)
	assert.Equal(t, int64(2), hs2.Conn)
	assert.Equal(t, "refused", hs2.Outcome)
	assert.False(t, hs2.Verified)
	require.NotNil(t, hs2.Peer, "the refused peer's certificate was presented")
	assert.Equal(t, "CN=denied", hs2.Peer.Subject)
	require.NotNil(t, hs2.Error)
	assert.Contains(t, *hs2.Error, "unauthorized")
	acl2 := recs[7].Body.(*ringtrace.ACL)
	assert.Equal(t, "deny", acl2.Decision)
	assert.Equal(t, "none", acl2.Rule)
	assert.Contains(t, acl2.Reason, "unauthorized")
	assert.Equal(t, "refused", recs[8].Body.(*ringtrace.Close).Reason)

	// /_shutdown: a request without a verified client certificate is refused
	// and recorded as unauthorized; one with a verified certificate the
	// tunnel ACL does not allow is refused and recorded as unauthorized with
	// the caller's identity; one the ACL allows stops the process and is
	// recorded with the caller's identity.
	origShutdown := *enableShutdown
	*enableShutdown = true
	defer func() { *enableShutdown = origShutdown }()
	rec := httptest.NewRecorder()
	s.env.statusMux().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/_shutdown", nil))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec = httptest.NewRecorder()
	s.env.statusMux().ServeHTTP(rec, verifiedRequest(http.MethodPost, "/_shutdown", "ops"))
	assert.Equal(t, http.StatusForbidden, rec.Code, "verified by the trust store, not allowed by --allow-cn allowed")
	rec = httptest.NewRecorder()
	s.env.statusMux().ServeHTTP(rec, verifiedRequest(http.MethodPost, "/_shutdown", "allowed"))
	assert.Equal(t, http.StatusOK, rec.Code)
	s.stop(t)

	trace, err := ringtrace.Read(traces)
	require.NoError(t, err)
	var shutdowns []*ringtrace.Shutdown
	for _, r := range trace.Boots[0].Records {
		if sd, ok := r.Body.(*ringtrace.Shutdown); ok {
			shutdowns = append(shutdowns, sd)
		}
	}
	require.Len(t, shutdowns, 3)
	assert.Equal(t, ringtrace.Shutdown{Source: "status-endpoint", Authorized: false, Peer: nil, Detail: shutdowns[0].Detail}, *shutdowns[0])
	ops, allowed := "CN=ops", "CN=allowed"
	assert.Equal(t, ringtrace.Shutdown{Source: "status-endpoint", Authorized: false, Peer: &ops, Detail: shutdowns[1].Detail}, *shutdowns[1])
	assert.Contains(t, shutdowns[1].Detail, "not allowed")
	assert.Equal(t, ringtrace.Shutdown{Source: "status-endpoint", Authorized: true, Peer: &allowed, Detail: "POST /_shutdown"}, *shutdowns[2])
}

// healthyStores lays out the four member stores with a fresh super
// heartbeat in the SPEC 3 shape the gate parses (see ringtrace/gate_test.go).
func healthyStores(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, m := range []string{"admin", "material", "super", "tunnel"} {
		for _, d := range []string{"heartbeat", "halts"} {
			require.NoError(t, os.MkdirAll(filepath.Join(root, m, d), 0o755))
		}
	}
	writeSuperHeartbeat(t, root, 42)
	return root
}

func writeSuperHeartbeat(t *testing.T, root string, seq int64) {
	t.Helper()
	previous := "null"
	if seq > 1 {
		previous = `"` + strings.Repeat("ab", 32) + `"`
	}
	line := fmt.Sprintf(`{"kind":"heartbeat","version":1,"observer":"super","sequence":%d,"timestamp":%q,"cadence_seconds":1,"checks":["member-fresh:tunnel"],"check_count":1,"observed":{"admin":null,"material":null,"tunnel":null},"previous":%s,"boot":null,"stop":false}`+"\n",
		seq, time.Now().UTC().Format("2006-01-02T15:04:05Z"), previous)
	require.NoError(t, os.WriteFile(filepath.Join(root, "super", "heartbeat", fmt.Sprintf("%010d.hb", seq)), []byte(line), 0o644))
}

// TestRingGateRefusesOnHalt: a healthy tree serves; a halt in one
// member's store refuses the next connection with the reason
// logged, a close with reason halt in the trace and /_status answering 503;
// clearing it with a fresh coordinator heartbeat serves again.
func TestRingGateRefusesOnHalt(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	stores := healthyStores(t)
	s := startRingServer(t, pki, traces, stores, 10*time.Second)

	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)
	assert.Equal(t, http.StatusOK, statusCode(s.env))
	// The close line is written when the copy loop sees the client's
	// EOF, after echoThrough has returned; the order asserted below needs
	// it in the trace before the refused connection's lines.
	records(t, traces, 1)

	halt := filepath.Join(stores, "material", "halt")
	require.NoError(t, os.WriteFile(halt, []byte(`{"kind":"halt",`), 0o644))
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "the gate refuses while a halt is in force")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	assert.Contains(t, s.logged(), "material/halt in force")

	recs := records(t, traces, 2)
	assert.Equal(t, "start accept handshake acl close accept close", kinds(recs))
	assert.Equal(t, ringtrace.Close{Conn: 2, Reason: "halt"}, ringtrace.Close{Conn: recs[6].Body.(*ringtrace.Close).Conn, Reason: recs[6].Body.(*ringtrace.Close).Reason})

	require.NoError(t, os.Remove(halt))
	writeSuperHeartbeat(t, stores, 43)
	got, err = echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err, "cleared halt and fresh heartbeat serve again")
	assert.Equal(t, "ping", got)
	assert.Equal(t, http.StatusOK, statusCode(s.env))

	// A stale coordinator heartbeat refuses too: the window is 10s.
	require.NoError(t, os.Remove(filepath.Join(stores, "super", "heartbeat", "0000000043.hb")))
	require.NoError(t, os.Remove(filepath.Join(stores, "super", "heartbeat", "0000000042.hb")))
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "no coordinator heartbeat refuses")
}

// TestRingEmitterFailureRefusesToServe: once an event cannot be recorded
// every later accept is refused and /_status answers 503. The failure is
// forced through the clock: a clock that goes backwards fails the emitter
// for good (ringtrace/README.md section 2).
func TestRingEmitterFailureRefusesToServe(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()

	origNow := ringNow
	defer func() { ringNow = origNow }()
	var back sync.Mutex
	broken := false
	ringNow = func() time.Time {
		back.Lock()
		defer back.Unlock()
		if broken {
			return time.Now().Add(-time.Hour)
		}
		return time.Now()
	}

	s := startRingServer(t, pki, traces, healthyStores(t), 10*time.Second)
	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)
	records(t, traces, 1)
	assert.Equal(t, http.StatusOK, statusCode(s.env))

	back.Lock()
	broken = true
	back.Unlock()
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "an accept that cannot be recorded is refused")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "the failure is sticky")
	assert.Contains(t, s.logged(), "clock went back")
}

// TestRingHaltClosesInFlightConnections: a connection already being served
// is closed the moment a halt appears, not left to drain. The refusal is
// re-evaluated on a timer, every in-flight connection is closed at once with
// a close line of reason halt, and the client's next read fails.
func TestRingHaltClosesInFlightConnections(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	stores := healthyStores(t)
	s := startRingServer(t, pki, traces, stores, 10*time.Second)

	conn, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: pki.pool, Certificates: []tls.Certificate{pki.allowed}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf), "the connection is served before the halt")

	require.NoError(t, os.WriteFile(filepath.Join(stores, "material", "halt"), []byte(`{"kind":"halt",`), 0o644))
	halted := time.Now()
	_, err = conn.Read(buf)
	require.Error(t, err, "the served connection is closed by the halt")
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("the connection was still open %s after the halt", time.Since(halted))
	}
	assert.Less(t, time.Since(halted), 2*time.Second, "closed within two seconds of the halt")

	recs := records(t, traces, 1)
	assert.Equal(t, "start accept handshake acl close", kinds(recs))
	closed := recs[4].Body.(*ringtrace.Close)
	assert.Equal(t, int64(1), closed.Conn)
	assert.Equal(t, "halt", closed.Reason, "the close line says why")
	assert.Contains(t, s.logged(), "material/halt in force")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
}

// reloadRecords returns the reload records of the single boot.
func reloadRecords(t *testing.T, traces string) []*ringtrace.Reload {
	t.Helper()
	trace, err := ringtrace.Read(traces)
	require.NoError(t, err)
	require.Len(t, trace.Boots, 1)
	var out []*ringtrace.Reload
	for _, r := range trace.Boots[0].Records {
		if rl, ok := r.Body.(*ringtrace.Reload); ok {
			out = append(out, rl)
		}
	}
	return out
}

// countReady replaces the readiness notification for the test and returns
// the count of notifications sent.
func countReady(t *testing.T) func() int {
	t.Helper()
	var mu sync.Mutex
	n := 0
	orig := readyNotifier
	readyNotifier = func() {
		mu.Lock()
		n++
		mu.Unlock()
	}
	t.Cleanup(func() { readyNotifier = orig })
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// TestRingFailedReloadRefusesToServe: a reload that fails leaves the process
// refusing to serve, not serving the previous material: /_status answers
// 503, accepts are refused, a connection in flight is closed, the reload
// line says failed with serving false, and READY is not re-sent. A later
// reload that succeeds clears it and re-sends READY.
func TestRingFailedReloadRefusesToServe(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	s := startRingServer(t, pki, traces, healthyStores(t), 10*time.Second)
	ready := countReady(t)

	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)
	records(t, traces, 1)

	// A connection in flight when the reload fails.
	conn, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: pki.pool, Certificates: []tls.Certificate{pki.allowed}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)

	good, err := os.ReadFile(pki.certPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(pki.certPath, []byte("not a certificate"), 0o644))
	s.env.reload()
	assert.Equal(t, 0, ready(), "READY is not re-sent after a failed reload")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "nothing is served on the previous material after a failed reload")
	_, err = conn.Read(buf)
	assert.Error(t, err, "the connection in flight is closed")
	assert.Contains(t, s.logged(), "last reload failed")

	reloads := reloadRecords(t, traces)
	require.Len(t, reloads, 1)
	assert.Equal(t, "failed", reloads[0].Outcome)
	assert.False(t, reloads[0].Serving, "serving is false after a failed reload")
	require.NotNil(t, reloads[0].Error)
	assert.Contains(t, *reloads[0].Error, "no certificates found")

	// The failure is sticky until a reload succeeds with every hash.
	require.NoError(t, os.WriteFile(pki.certPath, good, 0o644))
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env), "restoring the file is not a reload")
	s.env.reload()
	assert.Equal(t, 1, ready(), "READY is sent again once a reload succeeds")
	assert.Equal(t, http.StatusOK, statusCode(s.env))
	got, err = echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)
	reloads = reloadRecords(t, traces)
	require.Len(t, reloads, 2)
	assert.Equal(t, "ok", reloads[1].Outcome)
	assert.True(t, reloads[1].Serving)
	assert.Nil(t, reloads[1].Error)
	recs := records(t, traces, 4)
	closed := recs[len(recs)-1].Body.(*ringtrace.Close)
	assert.Equal(t, "eof", closed.Reason)
	halts := 0
	for _, r := range recs {
		if c, ok := r.Body.(*ringtrace.Close); ok && c.Reason == "halt" {
			halts++
		}
	}
	assert.Equal(t, 2, halts, "the connection in flight and the refused accept both closed with reason halt")
}

// TestRingFailedHashAtReloadRefusesToServe: material that cannot be hashed
// at reload is a failed reload even when the TLS reload itself succeeded:
// the reload line says failed, names the file, carries no hash for it, and
// serving stops until a reload succeeds with every hash.
func TestRingFailedHashAtReloadRefusesToServe(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	policy := filepath.Join(t.TempDir(), "policy.rego")
	require.NoError(t, os.WriteFile(policy, []byte("package x\n"), 0o644))
	s := startRingServerWith(t, pki, traces, healthyStores(t), 10*time.Second, func() { *serverAllowPolicy = policy })
	ready := countReady(t)

	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)

	require.NoError(t, os.Remove(policy))
	s.env.reload()
	assert.Equal(t, 0, ready(), "READY is not re-sent after a failed hash")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "material that cannot be hashed is not served on")

	reloads := reloadRecords(t, traces)
	require.Len(t, reloads, 1)
	assert.Equal(t, "failed", reloads[0].Outcome)
	assert.False(t, reloads[0].Serving)
	require.NotNil(t, reloads[0].Error)
	assert.Contains(t, *reloads[0].Error, "policy")
	var policyMaterial *ringtrace.Material
	for i := range reloads[0].Material {
		if reloads[0].Material[i].Material == "policy" {
			policyMaterial = &reloads[0].Material[i]
		}
	}
	require.NotNil(t, policyMaterial)
	assert.Nil(t, policyMaterial.SHA256, "no hash for a file that could not be read")

	require.NoError(t, os.WriteFile(policy, []byte("package x\n"), 0o644))
	s.env.reload()
	assert.Equal(t, 1, ready())
	assert.Equal(t, http.StatusOK, statusCode(s.env))
	got, err = echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)
	reloads = reloadRecords(t, traces)
	require.Len(t, reloads, 2)
	assert.Equal(t, "ok", reloads[1].Outcome)
	assert.True(t, reloads[1].Serving)
}

// TestACLRules: the start line's acl is exactly what the verifier applies,
// in the closed vocabulary, sorted and deduplicated, in both modes.
// TestRingConfigRecordsProxyProtocol pins the start line's proxy_protocol
// to the mode the tunnel listener's connections are handed to the backend
// with: each of proxy's modes by its trace name, and a mode the trace has
// no name for refused, so the process does not start with a start line
// that misdescribes what the backend receives.
func TestRingConfigRecordsProxyProtocol(t *testing.T) {
	// ringConfig hashes and returns the CA bundle the flag names, so the
	// test PKI's bundle stands in for it.
	pki := newRingPKI(t)
	savedCA := *caBundlePath
	*caBundlePath = pki.caPath
	t.Cleanup(func() { *caBundlePath = savedCA })
	for mode, want := range map[proxy.ProxyProtocolMode]string{
		proxy.ProxyProtocolOff: "off", proxy.ProxyProtocolConn: "conn", proxy.ProxyProtocolTLS: "tls", proxy.ProxyProtocolTLSFull: "tls-full",
	} {
		cfg, _, err := ringConfig("server", "a", "b", mode, nil, ringtrace.SandboxApplied, "", ringRules{acl: auth.ACL{AllowAll: true}})
		require.NoError(t, err)
		assert.Equal(t, want, cfg.ProxyProtocol)
		_, err = ringtrace.EncodeLine(ringtrace.Record{Sequence: 1, At: time.Now(), Body: &ringtrace.Start{Boot: 1, PID: 1, Config: cfg}})
		assert.NoError(t, err, "the recorded mode is in the format's set")
	}
	_, _, err := ringConfig("server", "a", "b", proxy.ProxyProtocolMode(99), nil, ringtrace.SandboxApplied, "", ringRules{acl: auth.ACL{AllowAll: true}})
	assert.Error(t, err, "a mode the trace cannot name is refused")
}

func TestACLRules(t *testing.T) {
	hash := "c" + strings.Repeat("2", 63)
	withPolicy := []ringtrace.Material{{Material: "policy", Path: "p.rego", SHA256: &hash}}
	pins, err := auth.ParseSPKIPins([]string{"sha256:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))})
	require.NoError(t, err)
	uris, err := wildcard.CompileList([]string{"spiffe://example/*"})
	require.NoError(t, err)
	opa := policy.WrapForTest(nil)

	cases := []struct {
		name     string
		mode     string
		rules    ringRules
		material []ringtrace.Material
		want     []string
	}{
		{"server allow-all", "server", ringRules{acl: auth.ACL{AllowAll: true}}, nil, []string{"allow-all"}},
		{"server disable-authentication wins", "server", ringRules{acl: auth.ACL{AllowAll: true}, disableAuth: true}, nil, []string{"disable-authentication"}},
		{"server pins only", "server", ringRules{acl: auth.ACL{AllowedPins: pins, AllowedCNs: []string{"x"}}}, nil, []string{"allow-spki-pin:sha256:" + strings.Repeat("ab", 32)}},
		{"server every list, sorted and deduplicated", "server", ringRules{
			acl:  auth.ACL{AllowedCNs: []string{"bob", "alice", "alice"}, AllowedOUs: []string{"eng"}, AllowedDNSs: []string{"a.example"}, AllowedIPs: []net.IP{net.IPv4(10, 0, 0, 1)}, AllowedURIs: uris},
			uris: []string{"spiffe://example/*"},
		}, nil, []string{"allow-cn:alice", "allow-cn:bob", "allow-dns:a.example", "allow-ip:10.0.0.1", "allow-ou:eng", "allow-uri:spiffe://example/*"}},
		{"server policy with its hash", "server", ringRules{acl: auth.ACL{AllowedCNs: []string{"alice"}, AllowOPAQuery: opa}}, withPolicy, []string{"allow-cn:alice", "policy:" + hash}},
		{"client hostname only", "client", ringRules{}, nil, []string{"verify-hostname"}},
		{"client rules and hostname", "client", ringRules{acl: auth.ACL{AllowedCNs: []string{"server"}, AllowedURIs: uris}, uris: []string{"spiffe://example/*"}}, nil, []string{"verify-cn:server", "verify-hostname", "verify-uri:spiffe://example/*"}},
		{"client pins skip hostname", "client", ringRules{acl: auth.ACL{AllowedPins: pins}}, nil, []string{"verify-spki-pin:sha256:" + strings.Repeat("ab", 32)}},
		{"client policy and no client certificate", "client", ringRules{acl: auth.ACL{AllowOPAQuery: opa}, disableAuth: true}, withPolicy, []string{"disable-authentication", "policy:" + hash, "verify-hostname"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := aclRules(c.mode, c.rules, c.material)
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
			cfg := ringtrace.Config{Mode: c.mode, Listen: "a", Target: "b", ProxyProtocol: ringtrace.ProxyProtocolOff, ACL: got, SandboxState: ringtrace.SandboxApplied, Material: []ringtrace.Material{}}
			_, err = ringtrace.EncodeLine(ringtrace.Record{Sequence: 1, At: time.Now(), Body: &ringtrace.Start{Boot: 1, PID: 1, Config: cfg}})
			assert.NoError(t, err, "every description is in the format's vocabulary")
		})
	}
	_, err = aclRules("server", ringRules{acl: auth.ACL{AllowOPAQuery: opa}}, nil)
	assert.Error(t, err, "a policy in force without a hash is refused")
}

// tickRecords returns the tick records of the single boot.
func tickRecords(t *testing.T, traces string) []ringtrace.Record {
	t.Helper()
	trace, err := ringtrace.Read(traces)
	require.NoError(t, err)
	require.Len(t, trace.Boots, 1)
	var out []ringtrace.Record
	for _, r := range trace.Boots[0].Records {
		if r.Body.Kind() == ringtrace.KindTick {
			out = append(out, r)
		}
	}
	return out
}

// TestRingTicks: the trace carries a heartbeat of its own, a tick line
// every --ring-tick, through the same path as every other line, so the
// ring can tell a dead emitter from a quiet one. Ticks stop when the trace
// is closed, and a sticky emitter failure stops them too.
func TestRingTicks(t *testing.T) {
	assert.Equal(t, []string{"5s"}, app.GetFlag("ring-tick").Model().Default)

	pki := newRingPKI(t)
	traces := t.TempDir()
	s := startRingServerWith(t, pki, traces, healthyStores(t), 10*time.Second, func() { *ringTick = 200 * time.Millisecond })
	time.Sleep(1100 * time.Millisecond)
	ticks := tickRecords(t, traces)
	require.GreaterOrEqual(t, len(ticks), 3, "at least three ticks in 1.1 s at 200 ms")
	for i := 1; i < len(ticks); i++ {
		assert.Equal(t, ticks[i-1].Sequence+1, ticks[i].Sequence, "ticks take sequences like every other line")
	}
	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got, "ticks do not disturb serving")

	s.stop(t)
	n := len(tickRecords(t, traces))
	time.Sleep(600 * time.Millisecond)
	assert.Equal(t, n, len(tickRecords(t, traces)), "ticks stop on close")
	trace, err := ringtrace.Read(traces)
	require.NoError(t, err)
	assert.False(t, trace.Boots[0].Torn)
}

// TestRingTicksStopOnEmitterFailure: a sticky emitter failure stops the
// ticks, which is how the ring notices it.
func TestRingTicksStopOnEmitterFailure(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	origNow := ringNow
	defer func() { ringNow = origNow }()
	var back sync.Mutex
	broken := false
	ringNow = func() time.Time {
		back.Lock()
		defer back.Unlock()
		if broken {
			return time.Now().Add(-time.Hour)
		}
		return time.Now()
	}
	s := startRingServerWith(t, pki, traces, healthyStores(t), 10*time.Second, func() { *ringTick = 100 * time.Millisecond })
	time.Sleep(400 * time.Millisecond)
	require.NotEmpty(t, tickRecords(t, traces))
	back.Lock()
	broken = true
	back.Unlock()
	time.Sleep(300 * time.Millisecond)
	n := len(tickRecords(t, traces))
	time.Sleep(400 * time.Millisecond)
	assert.Equal(t, n, len(tickRecords(t, traces)), "no tick is written after the emitter failed")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	assert.Contains(t, s.logged(), "clock went back")
}

// TestRingRecordsAcceptErrors: a failed Accept is an accept-error line
// with the error text and the backoff in milliseconds, through emit like
// every other line.
func TestRingRecordsAcceptErrors(t *testing.T) {
	traces := t.TempDir()
	emitter, err := ringtrace.Open(traces, ringtrace.Options{Config: ringtrace.Config{
		Mode: "server", Listen: "a", Target: "b", ProxyProtocol: ringtrace.ProxyProtocolOff, ACL: []string{"allow-all"}, SandboxState: ringtrace.SandboxApplied, Material: []ringtrace.Material{},
	}})
	require.NoError(t, err)
	r := &ring{emitter: emitter, stop: make(chan struct{})}
	r.AcceptError(errors.New("accept tcp 127.0.0.1:8443: too many open files"), 5*time.Millisecond)
	r.AcceptError(errors.New("accept tcp 127.0.0.1:8443: too many open files"), 10*time.Millisecond)
	r.close()

	trace, err := ringtrace.Read(traces)
	require.NoError(t, err)
	recs := trace.Boots[0].Records
	require.Len(t, recs, 3)
	assert.Equal(t, "start accept-error accept-error", kinds(recs))
	assert.Equal(t, ringtrace.AcceptError{Error: "accept tcp 127.0.0.1:8443: too many open files", BackoffMS: 5}, *recs[1].Body.(*ringtrace.AcceptError))
	assert.Equal(t, int64(10), recs[2].Body.(*ringtrace.AcceptError).BackoffMS)
	var _ proxy.Observer = r
}

// blockingListener is a listener whose Accept never returns: a wedged
// accept loop. It has no SetDeadline, so the loop cannot wake itself.
type blockingListener struct {
	inner net.Listener
	block chan struct{}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.block
	return nil, net.ErrClosed
}
func (l *blockingListener) Close() error   { close(l.block); return l.inner.Close() }
func (l *blockingListener) Addr() net.Addr { return l.inner.Addr() }

// TestWatchdogHealth: the watchdog's health is real. It is true only while
// the accept loop iterated within the health window, the emitter has no
// sticky error, the ring has no sticky refusal and the listener is open. A
// gate refusal in force (a halt) is not a reason to restart the process.
func TestWatchdogHealth(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	stores := healthyStores(t)
	s := startRingServer(t, pki, traces, stores, 10*time.Second)
	require.NotNil(t, s.env.proxy, "the environment holds the proxy the watchdog judges")
	deadline := time.Now().Add(3 * time.Second)
	for !s.env.healthy() {
		if time.Now().After(deadline) {
			t.Fatal("a serving proxy is healthy once its accept loop has iterated")
		}
		time.Sleep(20 * time.Millisecond)
	}

	halt := filepath.Join(stores, "material", "halt")
	require.NoError(t, os.WriteFile(halt, nil, 0o644))
	assert.NotEmpty(t, s.env.ring.refusal())
	assert.True(t, s.env.healthy(), "a halt in force refuses serving but is not a reason to restart the process")
	require.NoError(t, os.Remove(halt))

	s.env.ring.mu.Lock()
	s.env.ring.reloadFailed = errors.New("for the test")
	s.env.ring.mu.Unlock()
	assert.False(t, s.env.healthy(), "a sticky refusal is unhealthy")
	s.env.ring.mu.Lock()
	s.env.ring.reloadFailed = nil
	s.env.ring.mu.Unlock()
	assert.True(t, s.env.healthy())

	s.stop(t)
	assert.False(t, s.env.healthy(), "a shut-down proxy is not healthy")

	// A wedged accept loop: the listener never returns from Accept and has
	// no deadline to wake it, so the loop never iterates.
	t.Run("wedged accept loop", func(t *testing.T) {
		origWindow := acceptHealthWindow
		acceptHealthWindow = 300 * time.Millisecond
		defer func() { acceptHealthWindow = origWindow }()
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		wedged := &blockingListener{inner: inner, block: make(chan struct{})}
		env := newRingEnv(t, pki, t.TempDir(), healthyStores(t), 10*time.Second)
		cfg, ca, err := ringConfig("server", *serverListenAddress, *serverForwardAddress, proxy.ProxyProtocolOff, nil, sandboxState(), "", ringRules{acl: auth.ACL{AllowAll: true}})
		require.NoError(t, err)
		env.ring, err = openRing(cfg, ca, auth.ACL{AllowAll: true}, true, "")
		require.NoError(t, err)
		defer env.ring.close()
		p := proxy.New(wedged, time.Second, time.Second, 0, 0, env.dial, logger, 0, proxy.ProxyProtocolOff, proxy.NilMetrics())
		env.attachRing(p)
		go p.Accept()
		defer func() {
			p.Shutdown()
			p.Wait()
		}()
		time.Sleep(acceptHealthWindow + 200*time.Millisecond)
		assert.False(t, env.healthy(), "an accept loop that has not iterated within the window is unhealthy")
	})
}

// TestStatusListenerFailureIsStickyRefusal: an error from the status
// listener's Serve is not just logged: it is a sticky refusal, so the proxy
// refuses to serve (503, accepts refused, in-flight closed) until restart.
func TestStatusListenerFailureIsStickyRefusal(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	s := startRingServerWith(t, pki, traces, healthyStores(t), 10*time.Second, func() { *statusAddress = "http://" + freePort(t) })
	require.NotNil(t, s.env.statusListener, "the environment holds the status listener")
	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)
	assert.Equal(t, http.StatusOK, statusCode(s.env))

	// The listener fails out from under Serve.
	require.NoError(t, s.env.statusListener.Close())
	deadline := time.Now().Add(3 * time.Second)
	for s.env.ring.refusal() == "" {
		if time.Now().After(deadline) {
			t.Fatal("a status listener Serve error must become a refusal")
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.Contains(t, s.env.ring.refusal(), "status listener is down")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "accepts are refused after the status listener failed")
	assert.False(t, s.env.healthy(), "and the watchdog is not fed")
	assert.Equal(t, 1, strings.Count(s.logged(), "status listener failed"), "logged once")
	recs := records(t, traces, 2)
	assert.Equal(t, "halt", recs[len(recs)-1].Body.(*ringtrace.Close).Reason)
	// The trace says why: one refusal line naming the status listener,
	// before the halt that refused the second connection.
	refusals := 0
	for _, rec := range recs {
		if ref, ok := rec.Body.(*ringtrace.Refusal); ok {
			refusals++
			assert.Equal(t, "status-listener", ref.Source)
			assert.NotEmpty(t, ref.Error)
		}
	}
	assert.Equal(t, 1, refusals, "the status listener's death is recorded once")
}

// TestStatusListenerFailureWritesARefusalLine: the status listener's Serve
// error, which makes the proxy refuse until restart, is the one refusal
// line of the boot: source status-listener, the error as reported, written
// on the first failure and never again, with the refusal in force whether
// or not the line could be written.
func TestStatusListenerFailureWritesARefusalLine(t *testing.T) {
	r, traces, _ := handRing(t, "server", healthyStores(t))
	r.statusServeFailed(errors.New("accept tcp 127.0.0.1:6060: use of closed network connection"))
	r.statusServeFailed(errors.New("a second report of the same death"))
	assert.Contains(t, r.refusal(), "status listener is down")
	recs := traceRecords(t, traces)
	require.Equal(t, "refusal", kinds(recs))
	assert.Equal(t, ringtrace.Refusal{Source: "status-listener", Error: "accept tcp 127.0.0.1:6060: use of closed network connection"}, *recs[0].Body.(*ringtrace.Refusal))
}

// verifiedRequest is a request that arrived over TLS with a client
// certificate the listener verified: the leaf carries the given common
// name and stands in its own verified chain, as the ACL reads it.
func verifiedRequest(method, path, cn string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	return req
}

// TestPprofRequiresVerifiedClientCert: every /debug/pprof endpoint acts
// only for a caller with a verified client certificate, as /_shutdown
// does, and --enable-pprof is refused on a status listener that cannot
// verify one.
func TestPprofRequiresVerifiedClientCert(t *testing.T) {
	origProf, origArgs := *enableProf, os.Args
	*enableProf = true
	os.Args = []string{"ghostunnel", "--storepass=s3cret"}
	defer func() { *enableProf, os.Args = origProf, origArgs }()
	env := &Environment{}

	paths := []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/profile?seconds=1", "/debug/pprof/symbol", "/debug/pprof/trace?seconds=1", "/debug/pprof/heap"}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		env.statusMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s without a verified client certificate", path)
		assert.NotContains(t, rec.Body.String(), "profile", "%s serves nothing without a verified client certificate", path)
		assert.NotContains(t, rec.Body.String(), "ghostunnel", "%s serves nothing without a verified client certificate", path)

		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "ops"}}}}
		env.statusMux().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s with a certificate presented but not verified", path)
	}
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol"} {
		rec := httptest.NewRecorder()
		env.statusMux().ServeHTTP(rec, verifiedRequest(http.MethodGet, path, "ops"))
		assert.Equal(t, http.StatusOK, rec.Code, "%s with a verified client certificate", path)
	}
	rec := httptest.NewRecorder()
	env.statusMux().ServeHTTP(rec, verifiedRequest(http.MethodGet, "/debug/pprof/cmdline", "ops"))
	assert.Contains(t, rec.Body.String(), "--storepass=<redacted>", "still redacted for a verified caller")

	t.Run("refused on a plaintext status listener", func(t *testing.T) {
		t.Cleanup(saveRingFlags())
		origShutdown := *enableShutdown
		*enableShutdown = false
		t.Cleanup(func() { *enableShutdown = origShutdown })
		*statusAddress = "http://" + freePort(t)
		err := (&Environment{}).serveStatus()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--enable-pprof requires a TLS status listener")
	})
}

// TestShutdownAppliesTunnelACL: /_shutdown, after the verified-certificate
// check, holds the caller to the same server ACL the tunnel applies to
// its clients: a certificate the trust store verifies but the ACL does not
// allow is refused, recorded as unauthorized with the caller's identity.
// Where there is no server ACL to hold the caller to (client mode,
// --disable-authentication) nobody can stop the process over HTTP.
func TestShutdownAppliesTunnelACL(t *testing.T) {
	origShutdown := *enableShutdown
	*enableShutdown = true
	defer func() { *enableShutdown = origShutdown }()

	request := func(env *Environment, cn string) (int, bool) {
		rec := httptest.NewRecorder()
		env.statusMux().ServeHTTP(rec, verifiedRequest(http.MethodPost, "/_shutdown", cn))
		select {
		case <-env.shutdownChannel:
			return rec.Code, true
		default:
			return rec.Code, false
		}
	}
	server := func(acl auth.ACL) *Environment {
		return &Environment{ring: &ring{mode: "server", acl: acl, verifier: true}, shutdownChannel: make(chan bool, 1)}
	}

	env := server(auth.ACL{AllowedCNs: []string{"ops"}})
	code, requested := request(env, "intruder")
	assert.Equal(t, http.StatusForbidden, code, "verified by the trust store but not allowed by the ACL")
	assert.False(t, requested, "no shutdown was requested")
	code, requested = request(env, "ops")
	assert.Equal(t, http.StatusOK, code, "allowed by the ACL")
	assert.True(t, requested)

	code, requested = request(server(auth.ACL{AllowAll: true}), "anyone")
	assert.Equal(t, http.StatusOK, code, "--allow-all allows every verified caller")
	assert.True(t, requested)

	code, requested = request(server(auth.ACL{}), "ops")
	assert.Equal(t, http.StatusForbidden, code, "an empty ACL (--disable-authentication) allows nobody")
	assert.False(t, requested)

	client := &Environment{ring: &ring{mode: "client", acl: auth.ACL{AllowedCNs: []string{"ops"}}, verifier: true}, shutdownChannel: make(chan bool, 1)}
	code, requested = request(client, "ops")
	assert.Equal(t, http.StatusForbidden, code, "client mode has no tunnel ACL for callers")
	assert.False(t, requested)
}

// TestClientRequiresVerifyRuleOrHostnameOnly: client mode does not fall
// back to hostname-only verification silently. It refuses to start unless
// a --verify-* rule is given or the operator passes --verify-hostname-only,
// which is refused beside any other verification rule.
func TestClientRequiresVerifyRuleOrHostnameOnly(t *testing.T) {
	t.Cleanup(saveRingFlags())
	orig := []*[]string{clientAllowedCNs, clientAllowedOUs, clientAllowedDNSs, clientAllowedURIs, clientVerifySpkiPin}
	saved := make([][]string, len(orig))
	for i, p := range orig {
		saved[i] = *p
	}
	origIPs, origPolicy, origQuery := *clientAllowedIPs, *clientAllowPolicy, *clientAllowQuery
	origListen, origTarget, origHostnameOnly := *clientListenAddress, *clientForwardAddress, *clientVerifyHostnameOnly
	t.Cleanup(func() {
		for i, p := range orig {
			*p = saved[i]
		}
		*clientAllowedIPs, *clientAllowPolicy, *clientAllowQuery = origIPs, origPolicy, origQuery
		*clientListenAddress, *clientForwardAddress, *clientVerifyHostnameOnly = origListen, origTarget, origHostnameOnly
	})
	reset := func() {
		for _, p := range orig {
			*p = nil
		}
		*clientAllowedIPs, *clientAllowPolicy, *clientAllowQuery = nil, "", ""
		*clientVerifyHostnameOnly = false
		*certPath, *keyPath = "cert", "key"
		*clientListenAddress, *clientForwardAddress = "127.0.0.1:8081", "127.0.0.1:8443"
		*ringTraces, *ringStores, *ringHeartbeatMaxAge, *ringTick = "traces", "stores", 5*time.Second, time.Second
	}
	flag := clientCommand.GetFlag("verify-hostname-only")
	require.NotNil(t, flag, "--verify-hostname-only is a client-mode flag")
	assert.Equal(t, []string{"false"}, flag.Model().Default, "off unless the operator says so")

	reset()
	err := clientValidateFlags()
	require.Error(t, err, "no rule and no explicit acceptance of hostname-only verification")
	assert.Contains(t, err.Error(), "--verify-hostname-only")

	reset()
	*clientVerifyHostnameOnly = true
	assert.NoError(t, clientValidateFlags(), "hostname-only verification accepted explicitly")

	rules := map[string]func(){
		"--verify-cn":  func() { *clientAllowedCNs = []string{"server"} },
		"--verify-ou":  func() { *clientAllowedOUs = []string{"eng"} },
		"--verify-dns": func() { *clientAllowedDNSs = []string{"s.example"} },
		"--verify-ip":  func() { *clientAllowedIPs = []net.IP{net.IPv4(10, 0, 0, 1)} },
		"--verify-uri": func() { *clientAllowedURIs = []string{"spiffe://example/*"} },
		"--verify-spki-pin": func() {
			*clientVerifySpkiPin = []string{"sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 32))}
		},
		"--verify-policy": func() { *clientAllowPolicy, *clientAllowQuery = "policy", "query" },
	}
	for name, set := range rules {
		reset()
		set()
		assert.NoError(t, clientValidateFlags(), "%s is a rule", name)
		*clientVerifyHostnameOnly = true
		err := clientValidateFlags()
		if assert.Error(t, err, "--verify-hostname-only beside %s", name) {
			assert.Contains(t, err.Error(), "--verify-hostname-only is mutually exclusive")
		}
	}
}

// TestRingHaltDuringAcceptIsCaughtByTheWatch: the gate is read while the
// accept line is being made durable (ring.go, Accepted). A halt that lands
// after the gate has decided and before that decision is joined with the
// accept line (the window that holds the line's fsync) is not seen by that
// accept: the connection is served, as one accepted just before the halt
// would be, and the watch closes it within ringWatchInterval with a close
// line of reason halt. The halt is placed from the seam that runs at
// exactly that point, so Accepted cannot have returned before it landed.
func TestRingHaltDuringAcceptIsCaughtByTheWatch(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	stores := healthyStores(t)

	origDecided := ringGateDecided
	defer func() { ringGateDecided = origDecided }()
	var mu sync.Mutex
	armed := false
	haltPlaced := make(chan struct{})
	ringGateDecided = func() {
		mu.Lock()
		fire := armed
		armed = false
		mu.Unlock()
		if !fire {
			return
		}
		require.NoError(t, os.WriteFile(filepath.Join(stores, "material", "halt"), []byte(`{"kind":"halt",`), 0o644))
		close(haltPlaced)
	}
	s := startRingServer(t, pki, traces, stores, 10*time.Second)

	mu.Lock()
	armed = true
	mu.Unlock()
	conn, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: pki.pool, Certificates: []tls.Certificate{pki.allowed}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err, "the connection is served: the gate decided before the halt landed")
	require.Equal(t, "ping", string(buf))
	select {
	case <-haltPlaced:
	default:
		t.Fatal("the halt was not placed inside the accept")
	}
	halted := time.Now()

	_, err = conn.Read(buf)
	require.Error(t, err, "the served connection is closed by the watch")
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("the connection was still open %s after the halt", time.Since(halted))
	}
	assert.Less(t, time.Since(halted), 2*time.Second, "closed within the watch interval of the halt")

	recs := records(t, traces, 1)
	assert.Equal(t, "start accept handshake acl close", kinds(recs))
	closed := recs[4].Body.(*ringtrace.Close)
	assert.Equal(t, "halt", closed.Reason, "the close line says why")
	assert.Contains(t, s.logged(), "material/halt in force")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))

	// The next accept sees the halt itself: refused before any handshake.
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "the gate refuses the next connection")
}

// ---- the gate as a trivial call and one critical-path sync ----

// handRing builds a ring by hand over stores, as benchRing does: an emitter
// under SyncEveryLine, a gate with a one-hour heartbeat window and no
// verifier, the accept window and watch interval of the real ring, and a
// clock the test moves. No watcher is started unless the test asks.
func handRing(t *testing.T, mode, stores string) (*ring, string, *stateClock) {
	t.Helper()
	traces := t.TempDir()
	cfg := ringtrace.Config{
		Mode: mode, Listen: "127.0.0.1:8443", Target: "127.0.0.1:8080", ProxyProtocol: ringtrace.ProxyProtocolOff,
		ACL: []string{"disable-authentication"}, SandboxState: ringtrace.SandboxUnsupported,
		Material: []ringtrace.Material{{Material: "cert", Path: "/etc/gt/server.crt"}, {Material: "key", Path: "/etc/gt/server.key"}},
	}
	if mode == "client" {
		cfg.ACL = []string{"verify-hostname"}
	}
	goos := runtime.GOOS
	cfg.SandboxAccepted = &goos
	emitter, err := ringtrace.Open(traces, ringtrace.Options{Config: cfg, PID: 4242, Now: time.Now})
	require.NoError(t, err)
	t.Cleanup(func() { _ = emitter.Close() })
	clock := &stateClock{now: time.Now()}
	gate := ringtrace.NewGate(stores)
	gate.MaxHeartbeatAge = time.Hour
	state := ringtrace.NewGateState(gate, ringGateWindow, ringWatchInterval)
	state.Now = clock.Now
	t.Cleanup(state.Close)
	r := &ring{emitter: emitter, gate: state, mode: mode, stop: make(chan struct{})}
	return r, traces, clock
}

// stateClock is a clock moved by hand.
type stateClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stateClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stateClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func handConn() net.Conn {
	return benchConn{
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443},
		remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 51234},
	}
}

// traceRecords reads the single boot and returns its records after start,
// ticks excluded.
func traceRecords(t *testing.T, traces string) []ringtrace.Record {
	t.Helper()
	trace, err := ringtrace.Read(traces)
	require.NoError(t, err)
	require.Len(t, trace.Boots, 1)
	var out []ringtrace.Record
	for _, r := range trace.Boots[0].Records {
		if r.Body.Kind() == ringtrace.KindTick || r.Body.Kind() == ringtrace.KindStart {
			continue
		}
		out = append(out, r)
	}
	return out
}

const haltBody = `{"kind":"halt",`

// TestRingGateWindowIsPinnedBelowTheWatch: the reuse window is a small
// fraction of the watch interval, so a halt landing inside it is caught by
// the watch well within the bound a halt already has.
func TestRingGateWindowIsPinnedBelowTheWatch(t *testing.T) {
	assert.Less(t, ringGateWindow*10, ringWatchInterval, "the window must be below a tenth of the watch interval")
	assert.Greater(t, ringGateWindow, time.Duration(0))
}

// TestRingAcceptsShareOneGateScan: sixteen concurrent accepts on a healthy
// tree make one gate evaluation, and all are served.
func TestRingAcceptsShareOneGateScan(t *testing.T) {
	r, _, _ := handRing(t, "server", healthyStores(t))
	const accepts = 16
	var start, done sync.WaitGroup
	start.Add(1)
	errs := make([]error, accepts)
	for i := 0; i < accepts; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			obs, err := r.Accepted(handConn())
			errs[i] = err
			if err == nil {
				obs.Closed(proxy.CloseEOF)
			}
		}(i)
	}
	start.Done()
	done.Wait()
	for i, err := range errs {
		assert.NoError(t, err, "accept %d", i)
	}
	assert.Equal(t, int64(1), r.gate.Scans(), "one gate evaluation for sixteen concurrent accepts")
}

// TestRingAcceptReusesWithinTheWindow: without a watcher, two accepts 1 ms
// apart make one evaluation; 20 ms apart, two. A halt placed after an
// evaluation is seen by the first accept past the window.
func TestRingAcceptReusesWithinTheWindow(t *testing.T) {
	stores := healthyStores(t)
	r, traces, clock := handRing(t, "server", stores)
	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	obs.Closed(proxy.CloseEOF)
	clock.Advance(time.Millisecond)
	obs, err = r.Accepted(handConn())
	require.NoError(t, err)
	obs.Closed(proxy.CloseEOF)
	assert.Equal(t, int64(1), r.gate.Scans(), "two accepts 1 ms apart share one evaluation")
	clock.Advance(20 * time.Millisecond)
	obs, err = r.Accepted(handConn())
	require.NoError(t, err)
	obs.Closed(proxy.CloseEOF)
	assert.Equal(t, int64(2), r.gate.Scans(), "an accept 20 ms later evaluates again")

	require.NoError(t, os.WriteFile(filepath.Join(stores, "material", "halt"), []byte(haltBody), 0o644))
	clock.Advance(ringGateWindow + time.Nanosecond)
	_, err = r.Accepted(handConn())
	require.Error(t, err, "the first accept past the window sees the halt")
	assert.Contains(t, err.Error(), "material/halt in force")
	recs := traceRecords(t, traces)
	assert.Equal(t, "accept close accept close accept close accept close", kinds(recs))
	assert.Equal(t, "halt", recs[7].Body.(*ringtrace.Close).Reason)
}

// TestRingHaltIsSeenByTheNextAccept: with the watcher running, a halt
// placed after a serve decision is reported, and the next accept is
// refused with its accept and close(halt) lines; clearing it serves again.
func TestRingHaltIsSeenByTheNextAccept(t *testing.T) {
	stores := healthyStores(t)
	r, traces, clock := handRing(t, "server", stores)
	if err := r.gate.Watch(); err != nil {
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
			t.Fatalf("Watch on %s: %v", runtime.GOOS, err)
		}
		t.Skipf("no watcher on %s: %v", runtime.GOOS, err)
	}
	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	obs.Closed(proxy.CloseEOF)
	// Windows reports a file's last-write change only when the cache
	// flushes, so the tree healthyStores wrote may still report; let it,
	// then absorb it with one accept.
	time.Sleep(100 * time.Millisecond)
	obs, err = r.Accepted(handConn())
	require.NoError(t, err)
	obs.Closed(proxy.CloseEOF)
	// A tree that reports nothing is not scanned again, however long past
	// the window (the watch's own scan is what refreshes it in the proxy).
	scans, events := r.gate.Scans(), r.gate.Events()
	clock.Advance(500 * time.Millisecond)
	obs, err = r.Accepted(handConn())
	require.NoError(t, err)
	obs.Closed(proxy.CloseEOF)
	if r.gate.Events() == events {
		assert.Equal(t, scans, r.gate.Scans(), "a watched tree that reported nothing is not scanned again")
	} else {
		t.Logf("a late notification arrived; the reuse was not observable this time")
	}

	scans, events = r.gate.Scans(), r.gate.Events()
	halt := filepath.Join(stores, "material", "halt")
	require.NoError(t, os.WriteFile(halt, []byte(haltBody), 0o644))
	waitRingEvents(t, r, events)
	clock.Advance(time.Millisecond)
	_, err = r.Accepted(handConn())
	require.Error(t, err, "the accept after the watcher's event is refused")
	assert.Contains(t, err.Error(), "material/halt in force")
	assert.Equal(t, scans+1, r.gate.Scans(), "one scan, which saw the halt")

	events = r.gate.Events()
	require.NoError(t, os.Remove(halt))
	waitRingEvents(t, r, events)
	clock.Advance(time.Millisecond)
	obs, err = r.Accepted(handConn())
	require.NoError(t, err, "cleared: served again")
	obs.Closed(proxy.CloseEOF)

	recs := traceRecords(t, traces)
	assert.Equal(t, "accept close accept close accept close accept close accept close", kinds(recs))
	assert.Equal(t, ringtrace.Close{Conn: 4, Reason: "halt"}, ringtrace.Close{Conn: recs[7].Body.(*ringtrace.Close).Conn, Reason: recs[7].Body.(*ringtrace.Close).Reason})
}

func waitRingEvents(t *testing.T, r *ring, before int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for r.gate.Events() == before {
		if time.Now().After(deadline) {
			t.Fatalf("the watcher reported nothing within 2 s")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestRingServedConnectionPaysOneSync: the accept, handshake and acl lines
// of a served connection are one batch under one fsync, consecutive and in
// that order, written before the proxy dials and durable when Dialed
// returns; the close line is the second sync.
func TestRingServedConnectionPaysOneSync(t *testing.T) {
	r, traces, _ := handRing(t, "server", healthyStores(t))
	_, state := benchConnAndState()
	before := r.emitter.SyncCount()
	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	assert.Equal(t, int64(0), r.emitter.SyncCount()-before, "the accept pays no sync of its own")
	obs.Handshake(state, nil)
	require.NoError(t, obs.Dialed(nil, nil), "the record's commit is waited for in Dialed")
	assert.Equal(t, int64(1), r.emitter.SyncCount()-before, "accept, handshake and acl under one sync")
	obs.Closed(proxy.CloseEOF)
	assert.Equal(t, int64(2), r.emitter.SyncCount()-before, "the close is the second")

	recs := traceRecords(t, traces)
	assert.Equal(t, "accept handshake acl close", kinds(recs))
	for i, rec := range recs {
		assert.Equal(t, recs[0].Sequence+int64(i), rec.Sequence, "consecutive")
	}
	assert.Equal(t, int64(1), recs[0].Body.(*ringtrace.Accept).Conn)
	assert.Equal(t, "10.0.0.1:51234", recs[0].Body.(*ringtrace.Accept).Remote)
	assert.Equal(t, "ok", recs[1].Body.(*ringtrace.Handshake).Outcome)
	assert.Equal(t, "allow", recs[2].Body.(*ringtrace.ACL).Decision)
	assert.Equal(t, "eof", recs[3].Body.(*ringtrace.Close).Reason)
}

// TestRingRefusedHandshakeIsOneBatch: a handshake refused over the peer's
// certificate writes accept, handshake(refused) and acl(deny) together,
// then close(refused).
func TestRingRefusedHandshakeIsOneBatch(t *testing.T) {
	r, traces, _ := handRing(t, "server", healthyStores(t))
	_, state := benchConnAndState()
	before := r.emitter.SyncCount()
	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	obs.Handshake(state, errors.New("unauthorized: no client certificate"))
	assert.Equal(t, int64(1), r.emitter.SyncCount()-before, "accept, handshake and acl under one sync")
	obs.Closed(proxy.CloseRefused)
	recs := traceRecords(t, traces)
	assert.Equal(t, "accept handshake acl close", kinds(recs))
	hs := recs[1].Body.(*ringtrace.Handshake)
	assert.Equal(t, "refused", hs.Outcome)
	assert.False(t, hs.Verified)
	acl := recs[2].Body.(*ringtrace.ACL)
	assert.Equal(t, "deny", acl.Decision)
	assert.Equal(t, "none", acl.Rule)
	assert.Equal(t, "refused", recs[3].Body.(*ringtrace.Close).Reason)
}

// TestRingGateRefusedAcceptWritesAcceptAndClose: an accept the gate refuses
// writes its accept line and close(halt), and no handshake.
func TestRingGateRefusedAcceptWritesAcceptAndClose(t *testing.T) {
	stores := healthyStores(t)
	require.NoError(t, os.WriteFile(filepath.Join(stores, "admin", "fault"), []byte(`{"kind":"fault",`), 0o644))
	r, traces, _ := handRing(t, "server", stores)
	obs, err := r.Accepted(handConn())
	require.Error(t, err)
	assert.Nil(t, obs)
	assert.Contains(t, err.Error(), "admin/fault in force")
	recs := traceRecords(t, traces)
	assert.Equal(t, "accept close", kinds(recs))
	assert.Equal(t, int64(1), recs[0].Body.(*ringtrace.Accept).Conn)
	closed := recs[1].Body.(*ringtrace.Close)
	assert.Equal(t, int64(1), closed.Conn)
	assert.Equal(t, "halt", closed.Reason)
}

// TestRingConnectErrorStillWritesAccept: in client mode a dial that never
// reached TLS records no handshake; the accept line is then written with
// the close, so every connection's trace still begins with its accept.
func TestRingConnectErrorStillWritesAccept(t *testing.T) {
	r, traces, _ := handRing(t, "client", healthyStores(t))
	before := r.emitter.SyncCount()
	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	require.NoError(t, obs.Dialed(nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}))
	obs.Closed(proxy.CloseError)
	assert.Equal(t, int64(1), r.emitter.SyncCount()-before, "accept and close under one sync")
	recs := traceRecords(t, traces)
	assert.Equal(t, "accept close", kinds(recs))
	assert.Equal(t, "error", recs[1].Body.(*ringtrace.Close).Reason)
}

// ---- the record's commit overlaps the backend dial ----

// TestRingClientModeRecordsTheDialSynchronously: in client mode the
// handshake is the dial, so Dialed records accept, handshake and acl and
// returns only once they are durable: the sync is counted when Dialed
// returns, and the close is the second. The backend
// here never handshook, so it carries no server certificate: no rule
// names it, the record is a deny, and Dialed refuses the connection
// (TestRingNeverRecordsAnAllowUnderNoRule).
func TestRingClientModeRecordsTheDialSynchronously(t *testing.T) {
	r, traces, _ := handRing(t, "client", healthyStores(t))
	before := r.emitter.SyncCount()
	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	backend := tls.Client(handConn(), &tls.Config{MinVersion: tls.VersionTLS12})
	require.ErrorIs(t, obs.Dialed(backend, nil), errNoRule)
	assert.Equal(t, int64(1), r.emitter.SyncCount()-before, "accept, handshake and acl durable when Dialed returns")
	obs.Closed(proxy.CloseRefused)
	assert.Equal(t, int64(2), r.emitter.SyncCount()-before, "the close is the second")
	recs := traceRecords(t, traces)
	assert.Equal(t, "accept handshake acl close", kinds(recs))
	assert.Equal(t, "deny", recs[2].Body.(*ringtrace.ACL).Decision)
}

// heldTraceSync is a sync hook for the real emitter: the first sync after
// it is installed reports that it began and blocks until released; every
// later one passes straight through to the platform's sync.
type heldTraceSync struct {
	began   chan struct{}
	release chan struct{}
	once    sync.Once
	synced  atomic.Bool
}

func newHeldTraceSync() *heldTraceSync {
	return &heldTraceSync{began: make(chan struct{}, 1), release: make(chan struct{})}
}

func (h *heldTraceSync) hook(f *os.File) error {
	h.once.Do(func() {
		h.began <- struct{}{}
		<-h.release
		h.synced.Store(true)
	})
	return f.Sync()
}

// acceptOne accepts one connection on the listener in the background and
// hands it over on the returned channel.
func acceptOne(t *testing.T, backend net.Listener) <-chan net.Conn {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()
	return accepted
}

// awaitConn fails the test unless a connection arrives on ch within 5 s.
func awaitConn(t *testing.T, ch <-chan net.Conn, what string) net.Conn {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(5 * time.Second):
		t.Fatalf("%s within 5 s", what)
		return nil
	}
}

// TestRingRecordIsDurableBeforeAnyByteIsForwarded: the property the ring
// holds across the overlap. The commit of the served connection's accept,
// handshake and acl lines is held in the sync hook. Meanwhile the client
// completes its handshake and writes; the backend accepts the proxy's dial
// (the dial ran while the commit was held) and receives nothing while the
// commit is held. Once the sync is released the bytes flow both ways and
// the trace reads accept, handshake, acl(allow), close in order.
func TestRingRecordIsDurableBeforeAnyByteIsForwarded(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	s := startRingServerOn(t, pki, traces, healthyStores(t), 10*time.Minute, backend, func() { *ringTick = time.Minute })
	held := newHeldTraceSync()
	s.env.ring.emitter.SetSyncHook(held.hook)
	accepted := acceptOne(t, backend)

	conn, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: pki.pool, Certificates: []tls.Certificate{pki.allowed}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	// The dial happened while the record's commit was still held.
	dst := awaitConn(t, accepted, "the backend must see the dial")
	defer dst.Close()
	assert.False(t, held.synced.Load(), "the backend accepted the dial before the record was durable")
	select {
	case <-held.began:
	case <-time.After(5 * time.Second):
		t.Fatal("the record's commit never began")
	}
	assert.False(t, held.synced.Load(), "the commit is still held")
	// Nothing reaches the backend while the record is not durable: the
	// client's bytes sit unread in the proxy.
	_ = dst.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, err := dst.Read(make([]byte, 16))
	assert.Equal(t, 0, n, "no byte is forwarded before the record is durable")
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout(), "the backend side is open and silent, not closed: %v", err)

	close(held.release)
	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	_, err = io.ReadFull(dst, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf), "the bytes flow once the record is durable")
	_, err = dst.Write([]byte("pong"))
	require.NoError(t, err)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf))
	conn.Close()
	dst.Close()

	recs := records(t, traces, 1)
	assert.Equal(t, "start accept handshake acl close", kinds(recs))
	assert.Equal(t, "allow", recs[3].Body.(*ringtrace.ACL).Decision)
	for i := 2; i < len(recs); i++ {
		assert.Equal(t, recs[i-1].Sequence+1, recs[i].Sequence, "consecutive")
	}
}

// TestRingFailedCommitAfterTheDialClosesBothSidesBeforeAnyByte: the sync
// that was to make the served connection's record durable fails while the
// backend is already dialed. The client is closed without a reply; the
// backend saw the dial, received nothing and sees the connection closed;
// the ring logs the failed record and the abandoned connection, the proxy
// logs the refusal before forwarding; the failure is sticky: /_status
// answers 503 and the next connection is refused. The trace cannot hold
// the close line (the emitter is failed), so nothing about it is asserted
// beyond what a failed record leaves: no line after the record's.
func TestRingFailedCommitAfterTheDialClosesBothSidesBeforeAnyByte(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	s := startRingServerOn(t, pki, traces, healthyStores(t), 10*time.Minute, backend, func() { *ringTick = time.Minute })
	boom := errors.New("fsync: input/output error")
	s.env.ring.emitter.SetSyncHook(func(*os.File) error { return boom })
	accepted := acceptOne(t, backend)

	conn, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: pki.pool, Certificates: []tls.Certificate{pki.allowed}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err, "the handshake completes; the record fails after it")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte("ping"))

	dst := awaitConn(t, accepted, "the backend must see the dial")
	defer dst.Close()
	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := dst.Read(make([]byte, 16))
	assert.Equal(t, 0, n, "no byte reaches the backend")
	require.Error(t, err)
	var netErr net.Error
	if errors.As(err, &netErr) {
		assert.False(t, netErr.Timeout(), "the backend side is closed, not left open: %v", err)
	}

	n, err = conn.Read(make([]byte, 16))
	assert.Equal(t, 0, n, "the client gets no reply")
	require.Error(t, err, "the client is closed")
	if errors.As(err, &netErr) {
		assert.False(t, netErr.Timeout(), "closed, not left open: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(s.logged(), "refused before forwarding") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	logged := s.logged()
	assert.Contains(t, logged, "ring: a accept+handshake+acl event could not be recorded, refusing to serve until restart: ringtrace: fsync: fsync: input/output error")
	assert.Contains(t, logged, "ring: closing connection 1 from 127.0.0.1:")
	assert.Contains(t, logged, "refused before forwarding: ringtrace: fsync: fsync: input/output error")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env), "the failure is sticky")
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "the next connection is refused")

	trace, err := ringtrace.Read(traces)
	require.NoError(t, err)
	require.Len(t, trace.Boots, 1)
	for _, r := range trace.Boots[0].Records {
		assert.NotEqual(t, ringtrace.KindClose, r.Body.Kind(), "no close line can be written by a failed emitter")
	}
}

// ---- the chain store (the members' re-verification check) ----

// TestRingHandshakeCarriesTheChain: a served connection's handshake line
// names the chain the client presented; the file is under gt/chains/ and
// reads back as exactly the client's certificates; a second connection
// from the same client adds no file; a resumed handshake names the same
// chain; a refused handshake whose peer presented a chain names it too;
// and the trace root still reads with chains/ beside the boot. The bytes
// per connection with and without the chain key are logged.
func TestRingHandshakeCarriesTheChain(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	s := startRingServer(t, pki, traces, healthyStores(t), 10*time.Second)

	// A full handshake from the allowed client, then a resumed one (the
	// client keeps its session, and under TLS 1.3 the ticket arrives with
	// the reply, which the echo exchange reads before closing), then the
	// denied client, then the allowed client resumed again.
	cache := tls.NewLRUClientSessionCache(4)
	dialAllowed := func() bool {
		conn, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: pki.pool, Certificates: []tls.Certificate{pki.allowed}, MinVersion: tls.VersionTLS12, ClientSessionCache: cache})
		require.NoError(t, err)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)
		buf := make([]byte, 4)
		_, err = io.ReadFull(conn, buf)
		require.NoError(t, err)
		assert.Equal(t, "ping", string(buf))
		return conn.ConnectionState().DidResume
	}
	assert.False(t, dialAllowed(), "the first connection is a full handshake")
	resumed2 := dialAllowed()
	_, err := echoThrough(s.addr, pki, pki.denied)
	assert.Error(t, err, "a peer outside the allow list is refused")
	resumed4 := dialAllowed()

	// Every connection's accept, handshake and acl are one batch, so they
	// land in connection order; the close of one connection may land after
	// the next connection's batch, so the lines are taken by connection.
	recs := records(t, traces, 4)
	byConn := map[int64][]ringtrace.Record{}
	for _, r := range recs {
		switch b := r.Body.(type) {
		case *ringtrace.Accept:
			byConn[b.Conn] = append(byConn[b.Conn], r)
		case *ringtrace.Handshake:
			byConn[b.Conn] = append(byConn[b.Conn], r)
		case *ringtrace.ACL:
			byConn[b.Conn] = append(byConn[b.Conn], r)
		case *ringtrace.Close:
			byConn[b.Conn] = append(byConn[b.Conn], r)
		}
	}
	require.Len(t, byConn, 4)
	var handshakes []*ringtrace.Handshake
	for conn := int64(1); conn <= 4; conn++ {
		lines := byConn[conn]
		assert.Equal(t, "accept handshake acl close", kinds(lines), "connection %d", conn)
		handshakes = append(handshakes, lines[1].Body.(*ringtrace.Handshake))
	}

	// The served connection names the chain the client presented: the leaf
	// alone, so its name is the leaf's SHA-256, the peer fingerprint.
	leafDER := pki.allowed.Certificate[0]
	leafSum := sha256.Sum256(leafDER)
	want := hex.EncodeToString(leafSum[:])
	hs := handshakes[0]
	assert.Equal(t, "ok", hs.Outcome)
	assert.False(t, hs.Resumed)
	assert.Equal(t, want, hs.Chain, "the chain is named by the SHA-256 of the presented DER")
	assert.Equal(t, hs.Peer.Fingerprint, hs.Chain, "a one-certificate chain hashes as its leaf")
	path := ringtrace.ChainPath(traces, hs.Chain)
	assert.Equal(t, filepath.Join(traces, "chains", hs.Chain+".der"), path)
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, leafDER, stored, "the file is the presented DER")
	certs, data, err := ringtrace.ReadChain(traces, hs.Chain)
	require.NoError(t, err)
	assert.Equal(t, leafDER, data)
	require.Len(t, certs, 1)
	assert.Equal(t, "CN=allowed", certs[0].Subject.String())
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	assert.True(t, certs[0].Equal(leaf), "ReadChain returns the client's certificate")

	// The second connection from the same client resumed its session and
	// names the same chain, the stored session's, which the verifier
	// re-verified.
	require.True(t, resumed2, "the second connection of the allowed client resumed its session")
	assert.True(t, handshakes[1].Resumed)
	assert.True(t, handshakes[1].Verified)
	assert.Equal(t, want, handshakes[1].Chain, "a resumed handshake names the same chain")

	// The refused peer presented its chain before the refusal: named too,
	// and readable as CN=denied.
	denied := handshakes[2]
	assert.Equal(t, "refused", denied.Outcome)
	require.NotNil(t, denied.Peer)
	deniedSum := sha256.Sum256(pki.denied.Certificate[0])
	assert.Equal(t, hex.EncodeToString(deniedSum[:]), denied.Chain)
	certs, _, err = ringtrace.ReadChain(traces, denied.Chain)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "CN=denied", certs[0].Subject.String())

	// Resumed again after the denied peer: the same chain still.
	require.True(t, resumed4, "the third connection of the allowed client resumed its session")
	assert.True(t, handshakes[3].Resumed)
	assert.True(t, handshakes[3].Verified)
	assert.Equal(t, want, handshakes[3].Chain)

	// Two distinct chains, two files, no .tmp, and the root reads with
	// chains/ and material/ beside the boot.
	entries, err := os.ReadDir(filepath.Join(traces, "chains"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	wantNames := []string{denied.Chain + ".der", want + ".der"}
	sort.Strings(wantNames)
	assert.Equal(t, wantNames, names, "one file per distinct chain, nothing else")
	rootEntries, err := os.ReadDir(traces)
	require.NoError(t, err)
	names = nil
	for _, e := range rootEntries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{"0000000001", "chains", "lock", "material"}, names, "the boot, the chain store, the lock and the material store")

	// Bytes per connection: the served connection's four lines as written,
	// and the same four with the chain key left out.
	withChain, withoutChain := 0, 0
	for _, r := range byConn[1] {
		line, err := ringtrace.EncodeLine(r)
		require.NoError(t, err)
		withChain += len(line)
		if h, ok := r.Body.(*ringtrace.Handshake); ok {
			bare := *h
			bare.Chain = ""
			line, err = ringtrace.EncodeLine(ringtrace.Record{Sequence: r.Sequence, At: r.At, Body: &bare})
			require.NoError(t, err)
		}
		withoutChain += len(line)
	}
	t.Logf("bytes per served connection (accept+handshake+acl+close): %d with the chain key, %d without; the chain key adds %d", withChain, withoutChain, withChain-withoutChain)
	assert.Equal(t, len(`,"chain":""`)+64, withChain-withoutChain)
}

// orderedSyncs records, in order, every sync of the chain store and of the
// trace's segments, passing each through.
type orderedSyncs struct {
	mu    sync.Mutex
	order []string
}

func (o *orderedSyncs) chain(path string, f *os.File) error {
	o.mu.Lock()
	o.order = append(o.order, "chain:"+filepath.Base(path))
	o.mu.Unlock()
	if f == nil {
		return nil
	}
	return f.Sync()
}

func (o *orderedSyncs) segment(f *os.File) error {
	o.mu.Lock()
	o.order = append(o.order, "segment")
	o.mu.Unlock()
	return f.Sync()
}

func (o *orderedSyncs) list() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string{}, o.order...)
}

// chainState is a completed handshake state presenting the given
// certificates, leaf first.
func chainState(t *testing.T, ders ...[]byte) *tls.ConnectionState {
	t.Helper()
	state := &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		state.PeerCertificates = append(state.PeerCertificates, cert)
	}
	return state
}

// TestRingChainIsDurableBeforeTheHandshakeLine: with a hook recording the
// order of every sync, a served connection presenting a two-certificate
// chain syncs the chain file and its directory before the handshake
// batch's sync; the file holds the leaf's DER then the issuer's, in that
// order; the next connection with the same chain syncs nothing for it.
func TestRingChainIsDurableBeforeTheHandshakeLine(t *testing.T) {
	pki := newRingPKI(t)
	r, traces, _ := handRing(t, "server", healthyStores(t))
	caPEM, err := os.ReadFile(pki.caPath)
	require.NoError(t, err)
	caBlock, _ := pem.Decode(caPEM)
	require.NotNil(t, caBlock)
	leafDER, caDER := pki.allowed.Certificate[0], caBlock.Bytes
	state := chainState(t, leafDER, caDER)

	rec := &orderedSyncs{}
	r.emitter.SetSyncHook(rec.segment)
	ringtrace.SetChainSyncHook(rec.chain)
	t.Cleanup(func() { ringtrace.SetChainSyncHook(nil) })

	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	obs.Handshake(state, nil)
	require.NoError(t, obs.Dialed(nil, nil))
	hash := ringtrace.ChainHash(append(append([]byte{}, leafDER...), caDER...))
	assert.Equal(t, []string{"chain:" + filepath.Base(traces), "chain:" + hash + ".tmp", "chain:chains", "segment"}, rec.list(),
		"the chain file and its directory are synced before the handshake batch")
	obs.Closed(proxy.CloseEOF)

	recs := traceRecords(t, traces)
	assert.Equal(t, "accept handshake acl close", kinds(recs))
	hs := recs[1].Body.(*ringtrace.Handshake)
	assert.Equal(t, hash, hs.Chain)
	certs, data, err := ringtrace.ReadChain(traces, hash)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, leafDER...), caDER...), data, "leaf then issuer, in presented order")
	require.Len(t, certs, 2)
	assert.Equal(t, "CN=allowed", certs[0].Subject.String())
	assert.Equal(t, "CN=ring-test-ca", certs[1].Subject.String())

	// The same chain again: no chain sync, one file, the same name.
	before := len(rec.list())
	obs, err = r.Accepted(handConn())
	require.NoError(t, err)
	obs.Handshake(state, nil)
	require.NoError(t, obs.Dialed(nil, nil))
	obs.Closed(proxy.CloseEOF)
	assert.Equal(t, []string{"segment", "segment"}, rec.list()[before:], "a chain seen before is not written again")
	recs = traceRecords(t, traces)
	assert.Equal(t, hash, recs[5].Body.(*ringtrace.Handshake).Chain)
	entries, err := os.ReadDir(filepath.Join(traces, "chains"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, hash+".der", entries[0].Name())
}

// closableConn is handConn with a connection abandon can close.
type closableConn struct {
	benchConn
	closed atomic.Bool
}

func (c *closableConn) Close() error {
	c.closed.Store(true)
	return nil
}

// TestRingChainStoreFailureIsARecordFailure: a chain that cannot be stored
// (here, a regular file where chains/ must be) is a record that cannot be
// written: the connection is closed with its trace unrecorded, the failure
// is logged in the shape of a failed record and is sticky (refusal, the
// next accept refused, nothing more written, the close line included), and
// no line of the connection reaches the trace.
func TestRingChainStoreFailureIsARecordFailure(t *testing.T) {
	pki := newRingPKI(t)
	r, traces, _ := handRing(t, "server", healthyStores(t))
	require.NoError(t, os.WriteFile(filepath.Join(traces, "chains"), nil, 0o644))
	origLogger := logger
	sink := lockedBuffer{&sync.Mutex{}, &bytes.Buffer{}}
	logger = log.New(sink, "", 0)
	t.Cleanup(func() { logger = origLogger })

	conn := &closableConn{benchConn: handConn().(benchConn)}
	before := r.emitter.SyncCount()
	obs, err := r.Accepted(conn)
	require.NoError(t, err)
	obs.Handshake(chainState(t, pki.allowed.Certificate[0]), nil)
	assert.True(t, conn.closed.Load(), "the connection is abandoned")
	// As after a failed write of the batch: nothing is pending for Dialed
	// to wait on, and the connection it would forward is already closed.
	assert.NoError(t, obs.Dialed(nil, nil))
	obs.Closed(proxy.CloseError)
	assert.Equal(t, int64(0), r.emitter.SyncCount()-before, "nothing was written: not the handshake batch, not the close")

	sink.mu.Lock()
	logged := sink.buf.String()
	sink.mu.Unlock()
	assert.Contains(t, logged, "ring: a handshake event could not be recorded, refusing to serve until restart: ringtrace: chain: ")
	assert.Contains(t, logged, "is not a directory")
	assert.Contains(t, logged, "ring: closing connection 1 from 10.0.0.1:51234: its trace could not be recorded")
	assert.Contains(t, r.stickyRefusal(), "ring: trace failed: ringtrace: chain: ")
	_, err = r.Accepted(handConn())
	require.Error(t, err, "the failure is sticky")
	assert.Contains(t, err.Error(), "ringtrace: chain: ")
	assert.Nil(t, r.emitter.Err(), "the emitter itself is fine; the ring refuses on its own failure")

	require.NoError(t, os.Remove(filepath.Join(traces, "chains")))
	recs := traceRecords(t, traces)
	assert.Empty(t, recs, "no line of the connection reached the trace")
}

// TestRingCABundleIsStoredUnderItsHashAtStartAndReload: the CA bundle the
// start line hashes is under gt/material/<hash> with the bytes as hashed;
// a reload after the file at the same path was rewritten with another
// bundle records the new hash and stores the new bytes under it while the
// old file stays; a store that cannot be written (a regular file where
// material/ must be) is a failed reload, the line saying so with serving
// false and nothing served, until a reload succeeds with the store back.
func TestRingCABundleIsStoredUnderItsHashAtStartAndReload(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	s := startRingServer(t, pki, traces, healthyStores(t), 10*time.Second)
	ready := countReady(t)

	first, err := os.ReadFile(pki.caPath)
	require.NoError(t, err)
	firstHash := ringtrace.MaterialHash(first)
	recs := records(t, traces, 0)
	start := recs[0].Body.(*ringtrace.Start)
	var recorded *string
	for _, m := range start.Config.Material {
		if m.Material == "ca" {
			recorded = m.SHA256
		}
	}
	require.NotNil(t, recorded)
	assert.Equal(t, firstHash, *recorded, "the start line records the bundle's hash")
	stored, err := ringtrace.ReadMaterial(traces, firstHash)
	require.NoError(t, err, "the bundle is in the store under the start line's hash")
	assert.Equal(t, first, stored)

	// The same path, other bytes: the CA and the server's own certificate
	// appended, which the loader accepts and which still verifies the
	// clients. The reload records the new hash and stores the new bytes;
	// the old bytes stay under the old hash.
	serverPEM, err := os.ReadFile(pki.certPath)
	require.NoError(t, err)
	second := append(append([]byte{}, first...), serverPEM...)
	secondHash := ringtrace.MaterialHash(second)
	require.NotEqual(t, firstHash, secondHash)
	require.NoError(t, os.WriteFile(pki.caPath, second, 0o644))
	s.env.reload()
	assert.Equal(t, 1, ready())
	reloads := reloadRecords(t, traces)
	require.Len(t, reloads, 1)
	assert.Equal(t, "ok", reloads[0].Outcome)
	recorded = nil
	for _, m := range reloads[0].Material {
		if m.Material == "ca" {
			recorded = m.SHA256
		}
	}
	require.NotNil(t, recorded)
	assert.Equal(t, secondHash, *recorded, "the reload line records the rotated bundle's hash")
	stored, err = ringtrace.ReadMaterial(traces, secondHash)
	require.NoError(t, err, "the rotated bundle is in the store under the reload line's hash")
	assert.Equal(t, second, stored)
	stored, err = ringtrace.ReadMaterial(traces, firstHash)
	require.NoError(t, err, "the bundle the rotation replaced stays under its hash")
	assert.Equal(t, first, stored)
	got, err := echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)

	// A store that cannot be written: rotate again with the store gone
	// and a regular file in its place. The reload fails before its line,
	// which says so; nothing is served until a reload succeeds.
	third := append(append([]byte{}, second...), []byte("\n")...)
	thirdHash := ringtrace.MaterialHash(third)
	require.NoError(t, os.WriteFile(pki.caPath, third, 0o644))
	require.NoError(t, os.RemoveAll(filepath.Join(traces, "material")))
	require.NoError(t, os.WriteFile(filepath.Join(traces, "material"), nil, 0o644))
	s.env.reload()
	assert.Equal(t, 1, ready(), "READY is not re-sent after a reload whose bundle could not be stored")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env))
	_, err = echoThrough(s.addr, pki, pki.allowed)
	assert.Error(t, err, "nothing is served after a reload whose bundle could not be stored")
	assert.Contains(t, s.logged(), "unable to store the reloaded material")
	// The stray file is malformed to every reader of the root, so the
	// line is read once it is gone.
	require.NoError(t, os.Remove(filepath.Join(traces, "material")))
	reloads = reloadRecords(t, traces)
	require.Len(t, reloads, 2)
	assert.Equal(t, "failed", reloads[1].Outcome)
	assert.False(t, reloads[1].Serving)
	require.NotNil(t, reloads[1].Error)
	assert.Contains(t, *reloads[1].Error, "ringtrace: material: ")
	assert.Contains(t, *reloads[1].Error, "is not a directory")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode(s.env), "removing the file is not a reload")

	s.env.reload()
	assert.Equal(t, 2, ready())
	assert.Equal(t, http.StatusOK, statusCode(s.env))
	reloads = reloadRecords(t, traces)
	require.Len(t, reloads, 3)
	assert.Equal(t, "ok", reloads[2].Outcome)
	assert.True(t, reloads[2].Serving)
	stored, err = ringtrace.ReadMaterial(traces, thirdHash)
	require.NoError(t, err, "the bundle is stored once the store can be written")
	assert.Equal(t, third, stored)
	got, err = echoThrough(s.addr, pki, pki.allowed)
	require.NoError(t, err)
	assert.Equal(t, "ping", got)

}

// TestRingHandshakeRuleSurvivesAReloadDuringTheHandshake: the rule an acl
// line records is the verifier's own, read from the leaf the handshake
// parsed, and not what the verify cache holds afterwards. The verifier
// allows a peer under --allow-cn during the handshake; a reload's
// Invalidate lands between that decision and the observer's read (a client
// withholding its CertificateVerify holds that window open until
// --connect-timeout); the record is still allow under allow-cn, which is
// what every member's acl-substance computes from the chain, and never
// allow under none.
func TestRingHandshakeRuleSurvivesAReloadDuringTheHandshake(t *testing.T) {
	r, traces, _ := handRing(t, "server", healthyStores(t))
	pki := newRingPKI(t)
	cache := auth.NewVerifyCache(8)
	acl := auth.ACL{AllowedCNs: []string{"allowed"}}.WithVerifyCache(cache)
	verify := acl.VerifyPeerCertificateServerFor(pki.pool, time.Now)
	r.acl, r.verifier = acl, true

	obs, err := r.Accepted(handConn())
	require.NoError(t, err)
	raw := pki.allowed.Certificate
	require.NoError(t, verify(raw, nil), "the verifier allows the peer, as it does during the handshake")
	require.Equal(t, 1, cache.Len(), "and remembers the chain it verified")
	cache.Invalidate()
	require.Equal(t, 0, cache.Len(), "a reload forgets it before the handshake completes")

	state := chainState(t, raw...)
	obs.Handshake(state, nil)
	require.NoError(t, obs.Dialed(nil, nil), "the connection is served")
	obs.Closed(proxy.CloseEOF)

	recs := traceRecords(t, traces)
	require.Equal(t, "accept handshake acl close", kinds(recs))
	hs := recs[1].Body.(*ringtrace.Handshake)
	assert.True(t, hs.Verified)
	assert.Equal(t, ringtrace.ACL{Conn: 1, Decision: "allow", Rule: "allow-cn", Reason: "allowed by --allow-cn"}, *recs[2].Body.(*ringtrace.ACL))
	assert.Equal(t, "eof", recs[3].Body.(*ringtrace.Close).Reason)
}

// TestRingNeverRecordsAnAllowUnderNoRule: a completed handshake that no
// rule names cannot have been allowed by the verifier, so it is never
// recorded as an allow: the acl line says deny under none and the
// connection is refused before anything is forwarded (Dialed returns the
// refusal, the close says refused), in server and in client mode.
func TestRingNeverRecordsAnAllowUnderNoRule(t *testing.T) {
	for _, mode := range []string{"server", "client"} {
		t.Run(mode, func(t *testing.T) {
			r, traces, _ := handRing(t, mode, healthyStores(t))
			r.acl, r.verifier = auth.ACL{AllowedCNs: []string{"allowed"}}, true
			obs, err := r.Accepted(handConn())
			require.NoError(t, err)
			// A completed handshake with no certificate at all: nothing
			// the rules could have judged.
			state := &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			if mode == "server" {
				obs.Handshake(state, nil)
				err = obs.Dialed(nil, nil)
			} else {
				err = obs.Dialed(tls.Client(handConn(), &tls.Config{InsecureSkipVerify: true}), nil)
			}
			require.Error(t, err, "the connection is refused before anything is forwarded")
			obs.Closed(proxy.CloseRefused)
			recs := traceRecords(t, traces)
			require.Equal(t, "accept handshake acl close", kinds(recs))
			assert.False(t, recs[1].Body.(*ringtrace.Handshake).Verified, "nothing was verified")
			acl := recs[2].Body.(*ringtrace.ACL)
			assert.Equal(t, "deny", acl.Decision)
			assert.Equal(t, "none", acl.Rule)
			assert.Contains(t, acl.Reason, "no rule names the peer")
			assert.Equal(t, "refused", recs[3].Body.(*ringtrace.Close).Reason)
		})
	}
}
