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

package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// bulkBackend is a plain TCP backend for the bulk tests: it hands every
// accepted connection to serve.
func bulkBackend(tb testing.TB, serve func(net.Conn)) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	tb.Cleanup(func() { ln.Close() })
	return ln
}

// bulkProxy is a proxy with plain TCP on both legs, its accept loop
// running, with the given copy buffer, socket buffer and warm pool sizes
// (0 = the default for each).
func bulkProxy(tb testing.TB, backend net.Listener, copyBuf, sockBuf, warm int) (*Proxy, net.Listener) {
	tb.Helper()
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backend.Addr().String())
	}
	p := New(incoming, 5*time.Second, 5*time.Second, 0, 0, dialer, &testLogger{}, LogConnectionErrors, ProxyProtocolOff, NilMetrics())
	p.CopyBufferSize = copyBuf
	p.SocketBufferSize = sockBuf
	p.WarmBackendConnections = warm
	go p.Accept()
	tb.Cleanup(func() {
		p.Shutdown()
		p.Wait()
	})
	return p, incoming
}

// bulkCopy copies src to dst with a large buffer and the ReadFrom/WriteTo
// fast paths hidden, so the test's own ends never bound the throughput
// measured through the proxy.
func bulkCopy(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 1<<20)
	return io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, buf)
}

func closeWriteSide(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// TestCopyLoopForwardsExactBytes: the copy loop forwards exactly the bytes
// in both directions, whatever the buffer size, with a half-close in each
// direction: each side sends a 3 MiB random payload and half-closes, in
// both orders, and the other side receives it whole (compared by hash).
func TestCopyLoopForwardsExactBytes(t *testing.T) {
	const size = 3 << 20
	payloadToBackend := make([]byte, size)
	payloadToClient := make([]byte, size)
	if _, err := rand.Read(payloadToBackend); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(payloadToClient); err != nil {
		t.Fatal(err)
	}
	wantToBackend := sha256.Sum256(payloadToBackend)
	wantToClient := sha256.Sum256(payloadToClient)

	type result struct {
		sum [32]byte
		err error
	}
	// sendThenReceive writes the payload, half-closes, then reads to EOF;
	// receiveThenSend the other way round. In the backend-first order the
	// client first sends one trigger byte (a backend cannot know a client
	// is attached before a byte arrives, pooled or not), the backend then
	// sends and half-closes first, and the client sends and half-closes
	// last; the trigger byte is not part of the hashed payload.
	sendThenReceive := func(c net.Conn, payload []byte) result {
		if _, err := c.Write(payload); err != nil {
			return result{err: err}
		}
		closeWriteSide(c)
		h := sha256.New()
		if _, err := bulkCopy(h, c); err != nil {
			return result{err: err}
		}
		return result{sum: [32]byte(h.Sum(nil))}
	}
	receiveThenSend := func(c net.Conn, payload []byte) result {
		h := sha256.New()
		if _, err := bulkCopy(h, c); err != nil {
			return result{err: err}
		}
		if _, err := c.Write(payload); err != nil {
			return result{err: err}
		}
		closeWriteSide(c)
		return result{sum: [32]byte(h.Sum(nil))}
	}
	triggerThenReceiveThenSend := func(c net.Conn, payload []byte) result {
		if _, err := c.Write([]byte{'!'}); err != nil {
			return result{err: err}
		}
		return receiveThenSend(c, payload)
	}
	awaitTriggerThenSendThenReceive := func(c net.Conn, payload []byte) result {
		var trigger [1]byte
		if _, err := io.ReadFull(c, trigger[:]); err != nil {
			return result{err: err}
		}
		return sendThenReceive(c, payload)
	}

	for _, copyBuf := range []int{0, 32 << 10, 64 << 10, 256 << 10} {
		for _, warm := range []int{0, 2} {
			for _, clientFirst := range []bool{true, false} {
				name := fmt.Sprintf("buf=%d/warm=%d/clientFirst=%v", copyBuf, warm, clientFirst)
				t.Run(name, func(t *testing.T) {
					backendDone := make(chan result, 1)
					backend := bulkBackend(t, func(c net.Conn) {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(30 * time.Second))
						if clientFirst {
							backendDone <- receiveThenSend(c, payloadToClient)
						} else {
							backendDone <- awaitTriggerThenSendThenReceive(c, payloadToClient)
						}
					})
					_, incoming := bulkProxy(t, backend, copyBuf, 0, warm)

					client, err := net.Dial("tcp", incoming.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					_ = client.SetDeadline(time.Now().Add(30 * time.Second))
					var got result
					if clientFirst {
						got = sendThenReceive(client, payloadToBackend)
					} else {
						got = triggerThenReceiveThenSend(client, payloadToBackend)
					}
					if got.err != nil {
						t.Fatalf("client: %v", got.err)
					}
					if got.sum != wantToClient {
						t.Fatal("the client received other bytes than the backend sent")
					}
					var b result
					select {
					case b = <-backendDone:
					case <-time.After(30 * time.Second):
						t.Fatal("backend did not finish")
					}
					if b.err != nil {
						t.Fatalf("backend: %v", b.err)
					}
					if b.sum != wantToBackend {
						t.Fatal("the backend received other bytes than the client sent")
					}
				})
			}
		}
	}
}

// BenchmarkBulkThroughput streams 64 MiB through a real in-process proxy to
// an echo backend on loopback, plain TCP on both legs, and reports the
// throughput (the 64 MiB counted once, in the client-to-backend direction;
// the echo doubles the bytes the proxy moves) for each copy buffer size and
// socket buffer size. Run with:
//
//	go test -run '^$' -bench BenchmarkBulkThroughput -count=3 ./proxy/
func BenchmarkBulkThroughput(b *testing.B) {
	const size = 64 << 20
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}
	backend := bulkBackend(b, func(c net.Conn) {
		defer c.Close()
		_, _ = bulkCopy(c, c)
		closeWriteSide(c)
	})

	for _, sockBuf := range []int{0, 1 << 20, 4 << 20} {
		for _, copyBuf := range []int{32 << 10, 64 << 10, 128 << 10, 256 << 10, 1 << 20} {
			name := fmt.Sprintf("copy=%dK/sock=%dK", copyBuf>>10, sockBuf>>10)
			b.Run(name, func(b *testing.B) {
				_, incoming := bulkProxy(b, backend, copyBuf, sockBuf, 0)
				b.SetBytes(size)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					client, err := net.Dial("tcp", incoming.Addr().String())
					if err != nil {
						b.Fatal(err)
					}
					writeErr := make(chan error, 1)
					go func() {
						_, err := client.Write(payload)
						closeWriteSide(client)
						writeErr <- err
					}()
					n, err := bulkCopy(io.Discard, client)
					if err != nil {
						b.Fatal(err)
					}
					if err := <-writeErr; err != nil {
						b.Fatal(err)
					}
					if n != size {
						b.Fatalf("echoed %d bytes, want %d", n, size)
					}
					_ = client.Close()
				}
			})
		}
	}
}
