package main

// contentmemo.go is the memory a local check keeps, across cycles, of what
// it computed from bytes it reads every cycle: the result is keyed by the
// SHA-256 of exactly those bytes, taken over the bytes as read in the
// cycle that asks, so a result is reused only for bytes identical to the
// ones it was computed from, under the collision resistance every other
// content key in the ring rests on. The bytes are still read and hashed
// every cycle; what the memory spares is the computation. No part of a key
// is a size, a path or a modification time. A cycle forgets every key it
// did not ask for, so the memory holds at most what one cycle read.
//
// Every member carries a byte-identical copy of this file. A member uses
// only the memories its checks keep, so the rest is marked for the linter.

import "time"

// contentMemo is one such memory. A nil *contentMemo remembers nothing and
// computes every time.
//
//nolint:unused
type contentMemo[V any] struct {
	gen     uint64
	entries map[string]*contentEntry[V]
}

//nolint:unused
type contentEntry[V any] struct {
	v    V
	seen uint64
}

// begin starts a cycle's use of the memory.
//
//nolint:unused
func (m *contentMemo[V]) begin() {
	if m == nil {
		return
	}
	m.gen++
	if m.entries == nil {
		m.entries = map[string]*contentEntry[V]{}
	}
}

// end forgets every key the cycle did not ask for.
//
//nolint:unused
func (m *contentMemo[V]) end() {
	if m == nil {
		return
	}
	for k, e := range m.entries {
		if e.seen != m.gen {
			delete(m.entries, k)
		}
	}
}

// get returns the result remembered under sum, the SHA-256 of the bytes
// compute reads, or computes it now and remembers it. A result is never
// written to by its readers.
//
//nolint:unused
func (m *contentMemo[V]) get(sum string, compute func() V) V {
	if m == nil {
		return compute()
	}
	if e, ok := m.entries[sum]; ok {
		e.seen = m.gen
		return e.v
	}
	v := compute()
	m.entries[sum] = &contentEntry[V]{v: v, seen: m.gen}
	return v
}

// startLineDecode is what boot-ambiguous remembers of a start line
// (bootliveness.go): the pid its decode names, or the decode's error.
//
//nolint:unused
type startLineDecode struct {
	pid int64
	err error
}

// certificateParse is what material-loaded remembers of a certificate or
// CA bundle file (materialchecks.go): the validity window of each of its
// CERTIFICATE blocks in order, and whether it held at least one and every
// one parsed. Whether now is inside every window is judged every cycle.
//
//nolint:unused
type certificateParse struct {
	windows [][2]time.Time
	ok      bool
}
