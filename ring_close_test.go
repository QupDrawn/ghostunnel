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
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/certloader"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/ghostunnel/ghostunnel/ringtrace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRingCloseWaitsForTheTick: close returns only once the tick has, so
// no tick is written to the closed trace, which would fail it. The tick
// runs every millisecond so that it is due, or being written, whenever
// close runs; the round is repeated to catch the interleavings.
func TestRingCloseWaitsForTheTick(t *testing.T) {
	origLogger := logger
	logger = log.New(lockedBuffer{&sync.Mutex{}, &bytes.Buffer{}}, "", 0)
	t.Cleanup(func() { logger = origLogger })

	for i := 0; i < 50; i++ {
		traces := t.TempDir()
		emitter, err := ringtrace.Open(traces, ringtrace.Options{Config: ringtrace.Config{
			Mode: "server", Listen: "a", Target: "b", ProxyProtocol: ringtrace.ProxyProtocolOff, ACL: []string{"allow-all"}, SandboxState: ringtrace.SandboxApplied, Material: []ringtrace.Material{}, Binary: testRingBinary,
		}})
		require.NoError(t, err)
		r := &ring{emitter: emitter, stop: make(chan struct{})}
		r.startTick(time.Millisecond)
		time.Sleep(3 * time.Millisecond)
		r.close()
		time.Sleep(3 * time.Millisecond)
		require.NoError(t, r.stickyFailed(), "round %d: a tick was written after the trace was closed", i)
	}
}

// slowReloadSource counts the reloads it is asked for and takes delay
// over each, so that one is in progress whenever the shutdown comes.
type slowReloadSource struct {
	certloader.TLSConfigSource
	delay   time.Duration
	reloads atomic.Int64
}

func (s *slowReloadSource) Reload() error {
	s.reloads.Add(1)
	time.Sleep(s.delay)
	return s.TLSConfigSource.Reload()
}

func (s *slowReloadSource) LoadedFiles() (*certloader.LoadedFiles, bool) {
	return certloader.LoadedFilesOf(s.TLSConfigSource)
}

// TestServerStopsTheReloadsBeforeTheTraceCloses: serverListen starts the
// timed reloads once the ring is open and stops them, waiting for the one
// in progress, before it closes the trace: every reload that started is
// recorded, none runs after the return, and none writes to the closed
// trace.
func TestServerStopsTheReloadsBeforeTheTraceCloses(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
	source := &slowReloadSource{TLSConfigSource: env.tlsConfigSource, delay: 20 * time.Millisecond}
	env.tlsConfigSource = source
	savedReload := *timedReload
	t.Cleanup(func() { *timedReload = savedReload })
	*timedReload = 2 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- serverListen(env, nil) }()

	deadline := time.Now().Add(10 * time.Second)
	for source.reloads.Load() < 3 {
		require.False(t, time.Now().After(deadline), "no reload ran")
		time.Sleep(5 * time.Millisecond)
	}
	env.shutdownChannel <- true
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("serverListen did not return after shutdown")
	}

	started := source.reloads.Load()
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, started, source.reloads.Load(), "no reload runs once serverListen has returned")
	assert.NoError(t, env.ring.stickyFailed(), "nothing was written to the closed trace")
	assert.Len(t, reloadRecords(t, traces), int(started), "every reload that started is recorded")
}

// TestCloseRingWaitsForTheStatusHandlers: a status request in progress
// when the shutdown begins records what it records before the trace is
// closed: closeRing waits for the status listener's graceful shutdown.
func TestCloseRingWaitsForTheStatusHandlers(t *testing.T) {
	pki := newRingPKI(t)
	traces := t.TempDir()
	env := newRingEnv(t, pki, traces, healthyStores(t), 10*time.Second)
	sources := ringSources{tls: env.tlsConfigSource}
	cfg, ca, err := ringConfig("server", "a", "b", proxy.ProxyProtocolOff, nil, sandboxState(), sources, ringRules{acl: auth.ACL{AllowAll: true}})
	require.NoError(t, err)
	env.ring, err = openRing(cfg, ca, auth.ACL{AllowAll: true}, true, sources)
	require.NoError(t, err)

	entered := make(chan struct{})
	env.statusHTTP = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		time.Sleep(300 * time.Millisecond)
		env.ring.shutdownRequested("status-endpoint", false, nil, "POST /_shutdown refused: for test")
		w.WriteHeader(http.StatusForbidden)
	}), ReadHeaderTimeout: time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = env.statusHTTP.Serve(ln) }()
	go func() {
		resp, err := http.Post("http://"+ln.Addr().String()+"/_shutdown", "text/plain", nil)
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-entered

	// As the shutdown does: the status listener's shutdown is started on
	// its own, then the ring is closed once the proxy has drained.
	go env.stopStatus()
	env.closeRing()

	assert.NoError(t, env.ring.stickyFailed(), "nothing was written to the closed trace")
	recs := traceRecords(t, traces)
	require.NotEmpty(t, recs)
	assert.Equal(t, ringtrace.KindShutdown, recs[len(recs)-1].Body.Kind(), "the handler's line is recorded")
}
