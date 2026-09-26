/*-
 * Copyright 2026 Ghostunnel
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
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
)

// copyThrough runs one direction of a connection through p.copyData: input
// is written on the source pipe in one Write, the copy loop moves it to the
// destination pipe, and everything that arrives there before EOF is
// returned. copyData runs on the calling goroutine, so when copyThrough
// returns the copy, its buffer Put and the pipe closes are all done.
func copyThrough(t *testing.T, p *Proxy, input []byte) []byte {
	t.Helper()
	srcIn, srcOut := net.Pipe()
	dstIn, dstOut := net.Pipe()
	t.Cleanup(func() {
		srcIn.Close()
		srcOut.Close()
		dstIn.Close()
		dstOut.Close()
	})
	go func() {
		_, _ = srcIn.Write(input)
		srcIn.Close()
	}()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := io.ReadAll(dstOut)
		done <- result{out, err}
	}()
	if _, err := p.copyData(dstIn, srcOut); err != nil {
		t.Fatalf("copyData: %v", err)
	}
	r := <-done
	if r.err != nil && r.err != io.EOF && !isClosedConnectionError(r.err) {
		t.Fatalf("sink: %v", r.err)
	}
	return r.out
}

// pattern is n bytes that are all below 0x80 and never the sentinel, each
// stream distinguishable by its seed.
func pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = (byte(i)*7 + seed) & 0x7F
	}
	return out
}

// TestCopyDataPooledBufferIsScratch: the copy buffer is scratch that
// io.CopyBuffer writes into before it reads from, so a buffer full of
// another connection's bytes forwards none of them. Every buffer the copy
// loop can take is one buffer pre-filled with a sentinel (the pool starts
// empty, so its first Get calls New; the only pointer that ever enters the
// pool is that one), and for inputs from one byte to several buffers long
// the destination receives exactly the input, never a sentinel byte, while
// the sentinel stays in the buffer beyond what was read.
func TestCopyDataPooledBufferIsScratch(t *testing.T) {
	const sentinel = 0xA5
	p := proxyForTest(nil, nil)
	size := p.copyBufferSize()
	buf := bytes.Repeat([]byte{sentinel}, size)
	var news atomic.Int64
	p.pool.New = func() any {
		news.Add(1)
		return &buf
	}
	for i, n := range []int{1, 16, size - 1, size, size + 1, 3*size + 7} {
		input := pattern(n, byte(i+1))
		got := copyThrough(t, p, input)
		if !bytes.Equal(got, input) {
			t.Fatalf("input of %d bytes: destination received %d bytes that differ (first difference at %d)", n, len(got), firstDifference(got, input))
		}
		if bytes.IndexByte(got, sentinel) >= 0 {
			t.Fatalf("input of %d bytes: a sentinel byte reached the destination", n)
		}
		if n <= size {
			// The buffer was the one used: it carries this input, and
			// beyond it the sentinel (or an earlier, shorter input).
			if !bytes.Equal(buf[:n], input) {
				t.Fatalf("input of %d bytes: the pooled buffer does not carry it, so the copy did not use the pool", n)
			}
			if n < size && buf[size-1] != sentinel {
				t.Fatalf("input of %d bytes: the sentinel beyond the input was overwritten", n)
			}
		}
	}
	if news.Load() == 0 {
		t.Fatal("the copy loop never took a buffer from the pool")
	}
}

// TestCopyDataSequentialConnectionsForwardOwnBytes: two connections served
// one after the other through the same pooled buffer each forward exactly
// their own bytes. The first fills the whole buffer; the second, shorter,
// overwrites only its own length, and the first connection's bytes still
// sitting in the rest of the buffer are not forwarded. A third, empty
// connection forwards nothing.
func TestCopyDataSequentialConnectionsForwardOwnBytes(t *testing.T) {
	p := proxyForTest(nil, nil)
	size := p.copyBufferSize()
	shared := make([]byte, size)
	p.pool.New = func() any { return &shared }

	first := pattern(size, 1)
	if got := copyThrough(t, p, first); !bytes.Equal(got, first) {
		t.Fatalf("first connection: received %d bytes that differ (first difference at %d)", len(got), firstDifference(got, first))
	}
	if !bytes.Equal(shared, first) {
		t.Fatal("first connection: the pooled buffer does not carry its bytes, so the copy did not use the pool")
	}

	second := pattern(100, 2)
	if bytes.Equal(second, first[:100]) {
		t.Fatal("test setup: the two inputs must differ")
	}
	got := copyThrough(t, p, second)
	if !bytes.Equal(got, second) {
		t.Fatalf("second connection: received %d bytes that differ (first difference at %d)", len(got), firstDifference(got, second))
	}
	if !bytes.Equal(shared[:100], second) {
		t.Fatal("second connection: the pooled buffer does not carry its bytes, so it was not reused")
	}
	if !bytes.Equal(shared[100:], first[100:]) {
		t.Fatal("second connection: the first connection's bytes beyond the second's length should still be in the buffer")
	}

	if got := copyThrough(t, p, nil); len(got) != 0 {
		t.Fatalf("empty connection: received %d bytes from the buffer's stale content", len(got))
	}
}

func firstDifference(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
