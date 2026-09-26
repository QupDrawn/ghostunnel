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
	"container/list"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultVerifyCacheSize is the number of distinct peer chains a VerifyCache
// created for a ghostunnel process remembers before evicting the least
// recently used one.
const DefaultVerifyCacheSize = 1024

// VerifyCache remembers the outcome of VerifyPeerCertificateServer and
// VerifyPeerCertificateClient per distinct peer chain, so that a peer
// presenting the same certificates again (a reconnecting client, or a
// resumed session re-checked by certloader's VerifyConnection hook) is
// served the decision already made for those exact bytes instead of having
// the rules and the OPA policy run again. On a tunnel listener whose ACL
// verifies the client's chain itself (see VerifyPeerCertificateServerFor),
// the chain verification, the expensive part of a client-authenticated
// handshake, is remembered too: the chains a client's certificates
// verified to are kept with the decision, and a hit skips x509.Verify as
// well as the rules. A chain that did not verify is not remembered: its
// refusal may depend on the clock through any certificate involved,
// including a root in the pool, so it is computed afresh every time, as
// crypto/tls computes it.
//
// The cache is equivalent to verifying every time. The verifier is a pure
// function of five inputs: the peer's chain bytes, the trust material, the
// ACL rules, the OPA policy, and the clock. The key covers the first: it is a
// SHA-256 over every raw certificate the peer presented, in order, plus the
// verified leaf the verifier reads its subject and SANs from when crypto/tls
// built the chain. The generation covers the next three: Invalidate drops
// every entry, and the reload path calls it after every reload of trust
// material and policy, while the ACL rules never change for the life of a
// process. The clock is re-checked on every hit against the validity window
// of the chain the decision was made on, with the same clock the
// verification used (the TLS config's, when the chain was verified here),
// and a decision whose evaluation consulted the clock or the environment
// (an OPA policy calling time.now_ns, http.send and the like, see
// clockSensitiveBuiltins) is never stored; a chain verification that the
// platform performs live (a system root pool on Windows or macOS) is never
// stored either. Therefore every hit returns what a fresh verification would
// return now, and every change to an input either changes the key or bumps
// the generation.
//
// Every input is covered: a peer presenting different bytes gets a
// different key, and a peer cannot change what its bytes mean without
// changing them; an operator reloading material bumps the generation; nothing
// else changes the inputs.
//
// A cache is bound to exactly one ACL by ACL.WithVerifyCache. It is safe for
// concurrent use.
type VerifyCache struct {
	capacity int
	now      func() time.Time

	mu         sync.Mutex
	generation uint64
	entries    map[[sha256.Size]byte]*list.Element
	order      *list.List // front is the most recently used

	bound  atomic.Bool
	hits   atomic.Uint64
	misses atomic.Uint64
}

// verifyEntry is one remembered verification: the chains the peer's
// certificates verified to (crypto/tls's, or the ones built here; none in
// pin mode), the verifier's decision when it may be remembered (decided),
// the generation it was computed under, and the validity window of the
// chain it was computed on.
type verifyEntry struct {
	key        [sha256.Size]byte
	generation uint64
	chains     [][]*x509.Certificate
	decided    bool
	err        error
	notBefore  time.Time
	notAfter   time.Time
}

// NewVerifyCache returns an empty cache that remembers up to capacity
// decisions. A capacity below one is treated as DefaultVerifyCacheSize.
func NewVerifyCache(capacity int) *VerifyCache {
	if capacity < 1 {
		capacity = DefaultVerifyCacheSize
	}
	return &VerifyCache{
		capacity: capacity,
		now:      time.Now,
		entries:  make(map[[sha256.Size]byte]*list.Element),
		order:    list.New(),
	}
}

// WithVerifyCache returns a copy of the ACL whose verifiers consult cache.
// Every copy of the returned ACL shares the cache, which is the point: the
// TLS config's callback, the resumption hook and the ring's own checks all
// hold copies of one ACL. A cache can be bound once; binding it to a second
// ACL would let one ACL's decisions answer for another, so it panics.
func (a ACL) WithVerifyCache(cache *VerifyCache) ACL {
	if cache == nil {
		panic("auth: WithVerifyCache called with a nil cache")
	}
	if !cache.bound.CompareAndSwap(false, true) {
		panic("auth: a VerifyCache can be bound to one ACL only")
	}
	a.cache = cache
	return a
}

// Invalidate drops every remembered decision and starts a new generation.
// It must be called after every reload of trust material or policy, whether
// or not the reload succeeded: a reload that partly succeeded changed some
// of the inputs. Calling it on a nil cache does nothing.
func (c *VerifyCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.generation++
	c.entries = make(map[[sha256.Size]byte]*list.Element)
	c.order.Init()
	c.mu.Unlock()
}

// Stats reports how many verifications were served from the cache (the
// decision, or at least the chain verification) and how many were computed
// in full by the verifier.
func (c *VerifyCache) Stats() (hits, misses uint64) {
	if c == nil {
		return 0, 0
	}
	return c.hits.Load(), c.misses.Load()
}

// Len is the number of decisions currently remembered.
func (c *VerifyCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// verifyRole separates server-side from client-side decisions in the key.
type verifyRole byte

const (
	roleServer verifyRole = 's'
	roleClient verifyRole = 'c'
)

// verifyFunc is the verifier's core: the exact error to return, and whether
// the decision may be remembered (false when it depended on anything the
// key and the generation do not cover, such as a policy that consulted the
// clock, or an error that may not recur).
type verifyFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error, cacheable bool)

// chainFunc builds and verifies the chains for the presented certificates,
// as crypto/tls would have: the chains, or the exact error, and whether
// chains may be remembered (false when the platform verified the chain
// live).
type chainFunc func(rawCerts [][]byte) (chains [][]*x509.Certificate, err error, cacheable bool)

// verifyRequest is one verification through the cache. verifiedChains are
// the chains crypto/tls handed the callback; when buildChains is set the
// ACL verifies the chain itself and verifiedChains is ignored (it is empty
// under RequireAnyClientCert). now is the clock the chain verification
// uses, which the window re-check must use too; nil means the cache's own.
type verifyRequest struct {
	role           verifyRole
	rawCerts       [][]byte
	verifiedChains [][]*x509.Certificate
	buildChains    chainFunc
	now            func() time.Time
	decide         verifyFunc
}

// verify runs a request through the cache: a remembered decision for the
// same inputs, within its validity window and under the current
// generation, is returned; a remembered chain verification without a
// decision saves x509.Verify and the rules decide; otherwise everything
// runs and is remembered when it may be. A nil cache runs it all directly.
func (c *VerifyCache) verify(req verifyRequest) error {
	if c == nil {
		_, err := compute(req, nil, false)
		return err
	}
	key, ok := verifyKey(req.role, req.rawCerts, req.chainsForKey())
	if !ok {
		c.misses.Add(1)
		_, err := compute(req, nil, false)
		return err
	}
	clock := c.now
	if req.now != nil {
		clock = req.now
	}
	now := clock()
	entry, generation, hit := c.lookup(key, now)
	if hit && entry.decided {
		c.hits.Add(1)
		return entry.err
	}
	if hit {
		// The chain verification is remembered; only the decision is not.
		// Should this evaluation turn out to be one that may be, it is.
		c.hits.Add(1)
		fresh, err := compute(req, entry.chains, true)
		if fresh != nil && fresh.decided {
			fresh.key = key
			fresh.generation = generation
			c.store(fresh)
		}
		return err
	}
	c.misses.Add(1)
	fresh, err := compute(req, nil, false)
	// A decision is remembered only when the clock it was made on lies
	// inside the window it is remembered for; one made outside it (in pin
	// mode, where the window is the presented leaf's and the pin check
	// does not read the clock) is a decision the check makes afresh.
	if fresh != nil && !now.Before(fresh.notBefore) && !now.After(fresh.notAfter) {
		fresh.key = key
		fresh.generation = generation
		c.store(fresh)
	}
	return err
}

// chainsForKey is what the key covers besides the presented bytes: the
// verified leaf when crypto/tls built the chain, nothing when the ACL
// builds it (the presented bytes then determine the result).
func (req verifyRequest) chainsForKey() [][]*x509.Certificate {
	if req.buildChains != nil {
		return nil
	}
	return req.verifiedChains
}

// compute runs the request outside the cache: with the chain verification
// already known (known set: chains from a remembered entry), or from
// scratch. It returns the verifier's error and, when something may be
// remembered, the entry to store (without key and generation).
func compute(req verifyRequest, chains [][]*x509.Certificate, known bool) (*verifyEntry, error) {
	chainCacheable := true
	if req.buildChains != nil && !known {
		var err error
		chains, err, chainCacheable = req.buildChains(req.rawCerts)
		if err != nil {
			// A chain that did not verify is refused with the exact error,
			// and the rules never see it, as under crypto/tls's own
			// verification. The refusal is not remembered.
			return nil, err
		}
	} else if req.buildChains == nil {
		chains = req.verifiedChains
	}
	err, cacheable := req.decide(req.rawCerts, chains)
	if !chainCacheable || (req.buildChains == nil && !cacheable) {
		return nil, err
	}
	notBefore, notAfter, ok := validityWindow(req.rawCerts, chains)
	if !ok {
		return nil, err
	}
	return &verifyEntry{
		chains:    chains,
		decided:   cacheable,
		err:       err,
		notBefore: notBefore,
		notAfter:  notAfter,
	}, err
}

// lookup returns the remembered entry for key when there is one under the
// current generation and within its validity window at now, and the
// current generation, which a store of a verification computed now must
// carry. The generation is read under the same lock as the entries, so a
// verification computed after this lookup is stored only if no reload came
// in between.
func (c *VerifyCache) lookup(key [sha256.Size]byte, now time.Time) (entry *verifyEntry, generation uint64, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, found := c.entries[key]
	if !found {
		return nil, c.generation, false
	}
	entry = element.Value.(*verifyEntry)
	if entry.generation != c.generation {
		c.remove(element)
		return nil, c.generation, false
	}
	// The same predicate crypto/x509 applies: outside the window the
	// verification is not served, and the verifier decides again.
	if now.Before(entry.notBefore) || now.After(entry.notAfter) {
		c.remove(element)
		return nil, c.generation, false
	}
	c.order.MoveToFront(element)
	return entry, c.generation, true
}

// chainsFor is the verified chains remembered for key, when a chain
// verification is remembered under the current generation.
// It is a read for reporting, after the decision: it does not count as a
// hit, does not touch the recency order, and does not apply the window,
// which the decision already applied at the time it was made.
func (c *VerifyCache) chainsFor(key [sha256.Size]byte) ([][]*x509.Certificate, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element, found := c.entries[key]
	if !found {
		return nil, false
	}
	entry := element.Value.(*verifyEntry)
	if entry.generation != c.generation || len(entry.chains) == 0 {
		return nil, false
	}
	return entry.chains, true
}

// store remembers a verification computed under entry.generation, unless a
// reload has happened since (the generation moved on), in which case the
// verification may be about inputs that no longer exist and is dropped.
// The least recently used entry makes room when the cache is full.
func (c *VerifyCache) store(entry *verifyEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry.generation != c.generation {
		return
	}
	if element, found := c.entries[entry.key]; found {
		c.remove(element)
	}
	for c.order.Len() >= c.capacity {
		c.remove(c.order.Back())
	}
	c.entries[entry.key] = c.order.PushFront(entry)
}

// remove drops one entry; the lock is held.
func (c *VerifyCache) remove(element *list.Element) {
	delete(c.entries, element.Value.(*verifyEntry).key)
	c.order.Remove(element)
}

// verifyKey hashes what the verifier reads from its arguments: the role,
// the number of raw certificates, each raw certificate length-prefixed (so
// two chains that concatenate to the same bytes still differ), and whether
// there is a verified chain and, if so, its leaf's DER. ok is false when the
// arguments cannot be identified by bytes: a verified chain whose leaf has
// no DER (never the case for a chain crypto/tls built), or nothing at all.
func verifyKey(role verifyRole, rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (key [sha256.Size]byte, ok bool) {
	h := sha256.New()
	var n [8]byte
	h.Write([]byte{byte(role)})
	binary.BigEndian.PutUint64(n[:], uint64(len(rawCerts)))
	h.Write(n[:])
	for _, raw := range rawCerts {
		binary.BigEndian.PutUint64(n[:], uint64(len(raw)))
		h.Write(n[:])
		h.Write(raw)
	}
	switch {
	case len(verifiedChains) > 0 && len(verifiedChains[0]) > 0:
		leaf := verifiedChains[0][0]
		if len(leaf.Raw) == 0 {
			return key, false
		}
		h.Write([]byte{1})
		binary.BigEndian.PutUint64(n[:], uint64(len(leaf.Raw)))
		h.Write(n[:])
		h.Write(leaf.Raw)
	case len(rawCerts) == 0:
		return key, false
	default:
		h.Write([]byte{0})
	}
	h.Sum(key[:0])
	return key, true
}

// validityWindow is the interval in which every certificate of the verified
// chain is valid, or, when there is no verified chain (pin mode), the
// interval in which the presented leaf is. ok is false when no window can
// be read, in which case the verification is not remembered.
func validityWindow(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (notBefore, notAfter time.Time, ok bool) {
	if len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
		for i, cert := range verifiedChains[0] {
			if i == 0 || cert.NotBefore.After(notBefore) {
				notBefore = cert.NotBefore
			}
			if i == 0 || cert.NotAfter.Before(notAfter) {
				notAfter = cert.NotAfter
			}
		}
		return notBefore, notAfter, true
	}
	if len(rawCerts) == 0 {
		return notBefore, notAfter, false
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return notBefore, notAfter, false
	}
	return leaf.NotBefore, leaf.NotAfter, true
}
