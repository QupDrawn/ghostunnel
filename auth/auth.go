/*-
 * Copyright 2015 Square Inc.
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
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"time"

	// pin.hash.New() panics unless the hash implementation is linked into the
	// binary. These blank imports register the SHA-2 hashes referenced by
	// supportedSPKIPinHashes (crypto/sha512 registers SHA-384 as well as SHA-512),
	// so pinning does not depend on some other package importing them first.
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/wildcard"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// ACL represents an access control list for mutually-authenticated TLS connections.
// These options are disjunctive, if at least one attribute matches access will be granted.
type ACL struct {
	// AllowAll will allow all authenticated principals. If this option is set,
	// all other options are ignored as all principals with valid certificates
	// will be allowed no matter the subject.
	AllowAll bool

	// AllowCNs lists common names that should be allowed access. If a principal
	// has a valid certificate with at least one of these CNs, we grant access.
	AllowedCNs []string

	// AllowOUs lists organizational units that should be allowed access. If a
	// principal has a valid certificate with at least one of these OUs, we grant
	// access.
	AllowedOUs []string

	// AllowDNSs lists DNS SANs that should be allowed access. If a principal
	// has a valid certificate with at least one of these DNS SANs, we grant
	// access.
	AllowedDNSs []string

	// AllowIPs lists IP SANs that should be allowed access. If a principal
	// has a valid certificate with at least one of these IP SANs, we grant
	// access.
	AllowedIPs []net.IP

	// AllowURIs lists URI SANs that should be allowed access. If a principal
	// has a valid certificate with at least one of these URI SANs, we grant
	// access.
	AllowedURIs []wildcard.Matcher

	// AllowOPAQuery defines a rego precompiled query, ready to be verified
	// against the client certificate. This is exclusive with all other
	// options.
	AllowOPAQuery policy.Policy

	// OPAQueryTimeout sets the timeout for AllowOPAQuery. It has no effect
	// if AllowOPAQuery is nil.
	OPAQueryTimeout time.Duration

	// AllowedPins holds SPKI pins (see SPKIPin and ParseSPKIPins) of the expected peer's
	// SubjectPublicKeyInfo. When non-empty, verification uses out-of-band key
	// pinning (in the style of RFC 7858 section 4.2): the peer is authenticated
	// solely by requiring the leaf certificate's SPKI hash to match one of these
	// pins, and the certificate chain, validity period, and hostname are not
	// verified. Multiple pins may be supplied so that a current and a backup
	// key can both be accepted during key rotation. This is mutually exclusive
	// with all other ACL fields.
	AllowedPins []SPKIPin

	// cache remembers verification outcomes per peer chain; see VerifyCache
	// and WithVerifyCache. Nil means every verification runs the rules.
	cache *VerifyCache

	// chain, when set, makes the server verifier build and verify the
	// client's chain itself, against the trust material and clock of the
	// one TLS config it is bound to; see VerifyPeerCertificateServerFor.
	chain *clientChainVerifier
}

// supportedSPKIPinHashes maps the algorithm name accepted in the "<algo>:<digest>"
// pin syntax to its crypto.Hash.
var supportedSPKIPinHashes = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

// SPKIPin is a single SPKI pin: a hash algorithm and the expected digest of the
// peer's DER-encoded SubjectPublicKeyInfo. The digest is compared in constant
// time (see verifySPKIPin).
type SPKIPin struct {
	hash   crypto.Hash
	digest []byte
}

// ParseSPKIPins parses SPKI pins of the form "<algo>:<base64-digest>" (e.g.
// "sha256:..."). The algorithm prefix is required and must be one of the
// supported SHA-2 hashes. The digest must be base64-decodable and exactly
// hash.Size() bytes. Returns nil if pins is empty. Any invalid entry rejects
// the whole set, so malformed pins surface at startup rather than at
// listen/dial time.
func ParseSPKIPins(pins []string) ([]SPKIPin, error) {
	if len(pins) == 0 {
		return nil, nil
	}
	parsed := make([]SPKIPin, 0, len(pins))
	for _, p := range pins {
		pin, err := parseSPKIPin(p)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, pin)
	}
	return parsed, nil
}

func parseSPKIPin(s string) (SPKIPin, error) {
	algo, digest, ok := strings.Cut(s, ":")
	if !ok {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: expected format <algo>:<base64-digest>", s)
	}
	// Accept the algorithm prefix case-insensitively (e.g. "SHA256" as well as
	// "sha256"); supportedSPKIPinHashes is keyed on the lowercase form.
	algo = strings.ToLower(algo)
	hash, ok := supportedSPKIPinHashes[algo]
	if !ok {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: unsupported hash algorithm %q (supported: sha256, sha384, sha512)", s, algo)
	}
	// Any hash added to supportedSPKIPinHashes must also be linked in (see the
	// blank crypto/sha* imports above), otherwise hash.New() would panic
	// mid-handshake in verifySPKIPin. Reject here so a missing import fails
	// cleanly at flag-parse time instead.
	if !hash.Available() {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: hash algorithm %q is not available in this build", s, algo)
	}
	raw, err := base64.StdEncoding.DecodeString(digest)
	if err != nil {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: base64 decode failed: %w", s, err)
	}
	if len(raw) != hash.Size() {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: expected %d bytes for %s, got %d", s, hash.Size(), algo, len(raw))
	}
	return SPKIPin{hash: hash, digest: raw}, nil
}

// String is the pin as "<algo>:<hex-digest>": the non-secret form the ring's
// start line records (a pin is operator configuration, not a secret).
func (p SPKIPin) String() string {
	for name, hash := range supportedSPKIPinHashes {
		if hash == p.hash {
			return name + ":" + hex.EncodeToString(p.digest)
		}
	}
	return "unknown:" + hex.EncodeToString(p.digest)
}

// PinningEnabled reports whether this ACL authenticates peers via SPKI pinning
// (see AllowedPins). It is the single source of truth for pin mode: when it returns
// true, the transport MUST disable normal certificate verification
// (InsecureSkipVerify on clients, RequireAnyClientCert on servers) so that
// verifySPKIPin becomes the sole authentication check, and VerifyPeerCertificate{Server,Client}
// enforce the pin. Keeping both decisions derived from this one predicate
// prevents the transport and the verifier from drifting out of sync.
func (a ACL) PinningEnabled() bool {
	return len(a.AllowedPins) > 0
}

// verifySPKIPin checks whether the leaf certificate in rawCerts matches one of the
// configured SPKI pins. It is called when pinning is enabled, bypassing all
// chain-based verification. Each pin's hash is computed independently of the
// others, so multiple pins configured with different algorithms are all
// evaluated. The pin set is scanned sequentially and short-circuits on the
// first match; the pin set is operator configuration (not a secret), so only
// the individual digest comparison is constant-time (via subtle.ConstantTimeCompare).
func (a ACL) verifySPKIPin(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("unauthorized: no certificate presented")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("unauthorized: failed to parse certificate: %w", err)
	}

	spki := cert.RawSubjectPublicKeyInfo
	for _, pin := range a.AllowedPins {
		h := pin.hash.New()
		h.Write(spki)
		if subtle.ConstantTimeCompare(h.Sum(nil), pin.digest) == 1 {
			return nil
		}
	}

	return errors.New("unauthorized: pin verification failed")
}

// VerifyPeerCertificateServer is an implementation of VerifyPeerCertificate
// for crypto/tls.Config for servers terminating TLS connections that will
// enforce access controls based on the given ACL. If the given ACL is empty,
// no clients will be allowed (fails closed). With a VerifyCache bound (see
// WithVerifyCache), a peer chain already decided on is answered from the
// cache; the decision is the same one the rules would make now. On an ACL
// bound to a config's trust material (see VerifyPeerCertificateServerFor)
// the chain is built and verified here first, and verifiedChains, which
// crypto/tls leaves empty under RequireAnyClientCert, is not read.
func (a ACL) VerifyPeerCertificateServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	req := verifyRequest{role: roleServer, rawCerts: rawCerts, verifiedChains: verifiedChains, decide: a.verifyServer}
	if a.chain != nil && !a.PinningEnabled() {
		req.buildChains = a.chain.verify
		req.now = a.chain.now
	}
	return a.cache.verify(req)
}

// VerifyPeerCertificateServerFor is VerifyPeerCertificateServer for a
// tunnel listener whose config has ClientAuth RequireAnyClientCert, so
// that crypto/tls requires and parses the client's certificates but leaves
// verifying them to the callback returned here. The callback verifies the
// chain with exactly the options crypto/tls uses under
// RequireAndVerifyClientCert (GOROOT/src/crypto/tls/handshake_server.go,
// processCertsFromClient): Roots is roots, the ClientCAs the config
// carries; CurrentTime is now(), the config's clock (Config.Time, or
// time.Now when nil); Intermediates are every presented certificate after
// the leaf; KeyUsages is ExtKeyUsageClientAuth. A chain that does not
// verify is refused with the same *tls.CertificateVerificationError
// crypto/tls returns, before any rule runs; a chain that does is judged by
// the rules exactly as one crypto/tls built. With a VerifyCache bound, the
// verified chains are remembered under the presented bytes, within the
// chain's validity window on the config's clock and under the current
// generation, so a repeat of the same bytes skips x509.Verify; a refusal
// is never remembered and costs what it costs under crypto/tls; see
// VerifyCache for why that is the same decision.
//
// Doing this on the callback rather than in a VerifyConnection hook (where
// the parsed certificates are at hand) is deliberate: the cache is keyed by
// the raw bytes, so a hit needs no parsed certificate at all, and only a
// miss parses again what crypto/tls parsed, once per distinct chain per
// generation. Both hooks run at the same point of the handshake, after
// the certificates are read and before CertificateVerify, in TLS 1.2 and
// 1.3 alike, and a non-nil error from either makes crypto/tls send the
// bad_certificate alert.
//
// In pin mode (PinningEnabled) the chain is not verified; roots and now
// are unused. The binding is per config: a reload builds a new
// config with a new pool, and the callback for it is bound anew.
func (a ACL) VerifyPeerCertificateServerFor(roots *x509.CertPool, now func() time.Time) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if now == nil {
		now = time.Now
	}
	a.chain = &clientChainVerifier{roots: roots, now: now, live: rootsVerifiedLive(roots)}
	return a.VerifyPeerCertificateServer
}

// VerifiedChainsFor is the chains the server verifier verified the
// presented certificates to, for a consumer of
// tls.ConnectionState.VerifiedChains on a listener whose ACL verifies the
// chain itself (VerifiedChains is empty there). It is answered from
// the VerifyCache under the same content hash as the decision, whether the
// chain was built here or handed to the verifier by crypto/tls or
// go-spiffe (whose chains start with the presented leaf). ok is false when
// no verified chain is remembered for these bytes: no cache is bound, the
// chain did not verify, the chain was verified live by the platform, or
// the entry has since been evicted or invalidated by a reload.
func (a ACL) VerifiedChainsFor(rawCerts [][]byte) ([][]*x509.Certificate, bool) {
	if a.cache == nil || len(rawCerts) == 0 {
		return nil, false
	}
	if key, ok := verifyKey(roleServer, rawCerts, nil); ok {
		if chains, ok := a.cache.chainsFor(key); ok {
			return chains, true
		}
	}
	presentedLeaf := [][]*x509.Certificate{{&x509.Certificate{Raw: rawCerts[0]}}}
	if key, ok := verifyKey(roleServer, rawCerts, presentedLeaf); ok {
		return a.cache.chainsFor(key)
	}
	return nil, false
}

// clientChainVerifier is the server verifier's binding to one TLS
// config's trust material and clock, see VerifyPeerCertificateServerFor.
// live is whether the platform verifies chains against roots on every call
// (see rootsVerifiedLive), in which case no verification is remembered.
type clientChainVerifier struct {
	roots *x509.CertPool
	now   func() time.Time
	live  bool
}

// verify builds and verifies the chain for the presented certificates as
// crypto/tls does under RequireAndVerifyClientCert. The two errors
// crypto/tls refuses before the callback (no certificate, a certificate
// that does not parse) are refused here as well, in case the callback is
// ever reached otherwise.
func (v *clientChainVerifier) verify(rawCerts [][]byte) ([][]*x509.Certificate, error, bool) {
	if len(rawCerts) == 0 {
		return nil, errors.New("tls: client didn't provide a certificate"), false
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("tls: failed to parse client certificate: " + err.Error()), false
		}
		certs[i] = cert
	}
	opts := x509.VerifyOptions{
		Roots:         v.roots,
		CurrentTime:   v.now(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	chains, err := certs[0].Verify(opts)
	if err != nil {
		return nil, &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}, !v.live
	}
	return chains, nil, !v.live
}

// rootsVerifiedLive reports whether x509.Verify with these roots consults
// the platform's certificate store on every call, so that its result may
// change without the pool changing and must not be remembered. That is
// the case on Windows, macOS and iOS when roots is nil or is the pool
// SystemCertPool returned (crypto/x509 marks that pool and hands the
// chain to the platform verifier; CertPool.Equal compares the mark). A
// pool built from a CA bundle is verified by crypto/x509 itself, a pure
// function of the pool, everywhere; on other platforms so is the system
// pool, which is read once per process.
func rootsVerifiedLive(roots *x509.CertPool) bool {
	switch runtime.GOOS {
	case "windows", "darwin", "ios":
	default:
		return false
	}
	if roots == nil {
		return true
	}
	system, err := x509.SystemCertPool()
	if err != nil {
		return false
	}
	return roots.Equal(system)
}

// verifyServer is VerifyPeerCertificateServer's decision, with whether it
// may be remembered: the pin check and the rules depend on nothing but the
// chain and the configuration; a policy decision may be remembered only when
// the evaluation consulted nothing else (see evalPolicy), and a policy error
// never, as it may not recur.
func (a ACL) verifyServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (error, bool) {
	_, err, cacheable := a.decideServer(rawCerts, verifiedChains)
	return err, cacheable
}

// decideServer is the server verifier's decision, named: on allow, the
// rule it stopped at (allow-spki-pin, allow-all, allow-cn, allow-ou,
// allow-dns, allow-ip, allow-uri or policy), with the error on refusal
// and whether the decision may be remembered (verifyServer). The rule of
// an allow depends on nothing but the presented leaf and the configuration
// that lives for the process (the pins, AllowAll, the --allow-* lists, and
// whether a policy is configured; never on the trust material, the
// policy's text or the clock, which decide only whether the peer is
// allowed): that is what lets ServerRule name it again from the leaf
// alone, after the handshake, and TestServerRuleIsTheVerifiersRule holds
// the two to each other.
func (a ACL) decideServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (rule string, err error, cacheable bool) {
	if a.PinningEnabled() {
		if err := a.verifySPKIPin(rawCerts); err != nil {
			return "", err, true
		}
		return "allow-spki-pin", nil, true
	}

	if len(verifiedChains) == 0 {
		return "", errors.New("unauthorized: invalid principal, or principal not allowed"), true
	}

	// If --allow-all has been set, a valid cert is sufficient to connect.
	if a.AllowAll {
		return "allow-all", nil, true
	}

	cert := verifiedChains[0][0]

	// Check the subject and SANs against the --allow-* flags.
	if rule := a.matchingRule(cert, &allowRuleNames); rule != "" {
		return rule, nil, true
	}

	// Check against OPA
	if a.AllowOPAQuery != nil {
		allowed, cacheable, err := a.evalPolicy(cert)
		if err != nil {
			return "", err, false
		}
		if allowed {
			return "policy", nil, cacheable
		}
		return "", errors.New("unauthorized: invalid principal, or principal not allowed"), cacheable
	}

	return "", errors.New("unauthorized: invalid principal, or principal not allowed"), true
}

// evalPolicy runs the OPA policy on the certificate and reports whether it
// allowed the peer. cacheable is false when the evaluation called a builtin
// whose result depends on the clock or the environment rather than on the
// certificate and the policy (see clockSensitiveBuiltins): such a decision
// may change without the certificate or the policy changing, so a
// VerifyCache must not remember it.
func (a ACL) evalPolicy(cert *x509.Certificate) (allowed, cacheable bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.OPAQueryTimeout)
	defer cancel()
	input := map[string]any{
		"certificate": cert,
	}
	tracer := &clockTracer{}
	results, err := a.AllowOPAQuery.Eval(ctx, rego.EvalInput(input), rego.EvalQueryTracer(tracer))
	if err != nil {
		return false, false, fmt.Errorf("unauthorized: policy returned error: %w", err)
	}
	return results.Allowed(), !tracer.sensitive, nil
}

// clockSensitiveBuiltins are the OPA builtins whose result depends on the
// wall clock even though OPA does not mark them non-deterministic:
// io.jwt.decode_verify checks exp and nbf against the evaluation's time, and
// the crypto.x509.parse_and_verify_certificates builtins check validity
// against it. Builtins OPA marks non-deterministic (time.now_ns, http.send,
// rand.intn, uuid.rfc4122, opa.runtime, net.lookup_ip_addr, the JWT
// signers) are recognised by that mark.
var clockSensitiveBuiltins = map[string]bool{
	"io.jwt.decode_verify":                                   true,
	"crypto.x509.parse_and_verify_certificates":              true,
	"crypto.x509.parse_and_verify_certificates_with_options": true,
}

// clockTracer watches one policy evaluation for a call to a builtin whose
// result is not a function of the input and the policy. OPA reports every
// expression about to be evaluated, before it runs, so a call is seen
// whether it then succeeds, fails or is undefined.
type clockTracer struct {
	sensitive bool
}

func (t *clockTracer) Enabled() bool { return !t.sensitive }

func (t *clockTracer) Config() topdown.TraceConfig { return topdown.TraceConfig{} }

func (t *clockTracer) TraceEvent(event topdown.Event) {
	if t.sensitive || event.Op != topdown.EvalOp {
		return
	}
	expr, ok := event.Node.(*ast.Expr)
	if !ok || !expr.IsCall() {
		return
	}
	name := expr.Operator().String()
	if clockSensitiveBuiltins[name] {
		t.sensitive = true
		return
	}
	if builtin := ast.BuiltinMap[name]; builtin != nil && builtin.Nondeterministic {
		t.sensitive = true
	}
}

// ServerRule names the rule under which VerifyPeerCertificateServer allows
// a peer with the given certificates and verified chains, as a flag name:
// allow-spki-pin, allow-all, allow-cn, allow-ou, allow-dns, allow-ip,
// allow-uri, or policy. It walks the same checks in the same order and stops
// where the verifier stops (decideServer). The policy is not evaluated
// again: on a handshake the verifier let through with no other rule
// matching, the policy is what allowed it. "none" means nothing here allows
// the peer.
//
// It reads only the leaf, verifiedChains[0][0], and the verifier's chain
// starts with the presented leaf whoever built it (crypto/x509, crypto/tls
// or go-spiffe), so a caller that holds the leaf the handshake parsed and
// knows the verifier allowed the peer names the verifier's rule by passing
// that leaf as a chain of one; it needs no cache and no chain the verifier
// remembered. That is how the ring records a served connection (ring.go,
// Handshake): a reload between the verifier's decision and the record
// cannot change the answer.
func (a ACL) ServerRule(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) string {
	if a.PinningEnabled() {
		return "allow-spki-pin"
	}
	if len(verifiedChains) == 0 {
		return "none"
	}
	if a.AllowAll {
		return "allow-all"
	}
	if rule := a.matchingRule(verifiedChains[0][0], &allowRuleNames); rule != "" {
		return rule
	}
	if a.AllowOPAQuery != nil {
		return "policy"
	}
	return "none"
}

// ClientRule is ServerRule for VerifyPeerCertificateClient: verify-spki-pin,
// hostname (an empty ACL leaves the decision to crypto/tls hostname
// verification), verify-cn, verify-ou, verify-dns, verify-ip, verify-uri,
// policy, or none.
func (a ACL) ClientRule(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) string {
	if a.PinningEnabled() {
		return "verify-spki-pin"
	}
	if len(verifiedChains) == 0 {
		return "none"
	}
	if a.empty() {
		return "hostname"
	}
	if rule := a.matchingRule(verifiedChains[0][0], &verifyRuleNames); rule != "" {
		return rule
	}
	if a.AllowOPAQuery != nil {
		return "policy"
	}
	return "none"
}

// empty reports whether no subject, SAN or policy rule is configured.
func (a ACL) empty() bool {
	return len(a.AllowedCNs) == 0 && len(a.AllowedOUs) == 0 && len(a.AllowedDNSs) == 0 && len(a.AllowedURIs) == 0 && len(a.AllowedIPs) == 0 && a.AllowOPAQuery == nil
}

// ruleNames are the flag names matchingRule answers with, one set per
// role, spelled once so that naming a rule builds no string per handshake.
type ruleNames struct {
	cn, ou, dns, ip, uri string
}

var (
	allowRuleNames  = ruleNames{"allow-cn", "allow-ou", "allow-dns", "allow-ip", "allow-uri"}
	verifyRuleNames = ruleNames{"verify-cn", "verify-ou", "verify-dns", "verify-ip", "verify-uri"}
)

// matchingRule checks the leaf certificate's subject and SANs against the
// configured lists, in order, and returns the name of the first flag that
// matches (prefix-cn, prefix-ou, prefix-dns, prefix-ip, prefix-uri, with
// prefix "allow" on the server, allowRuleNames, and "verify" on the
// client, verifyRuleNames), or "" when none does.
func (a ACL) matchingRule(cert *x509.Certificate, names *ruleNames) string {
	// Check CN against --allow-cn / --verify-cn flag(s).
	if slices.Contains(a.AllowedCNs, cert.Subject.CommonName) {
		return names.cn
	}

	// Check OUs against --allow-ou / --verify-ou flag(s).
	if intersects(a.AllowedOUs, cert.Subject.OrganizationalUnit) {
		return names.ou
	}

	// Check DNS SANs against --allow-dns / --verify-dns flag(s).
	if intersects(a.AllowedDNSs, cert.DNSNames) {
		return names.dns
	}

	// Check IP SANs against --allow-ip / --verify-ip flag(s).
	if intersectsIP(a.AllowedIPs, cert.IPAddresses) {
		return names.ip
	}

	// Check URI SANs against --allow-uri / --verify-uri flag(s).
	if intersectsURI(a.AllowedURIs, cert.URIs) {
		return names.uri
	}

	return ""
}

// VerifyPeerCertificateClient is an implementation of VerifyPeerCertificate
// for crypto/tls.Config for clients initiating TLS connections that will
// validate the server certificate based on the given ACL. If the ACL is empty,
// all servers will be allowed (this function assumes that DNS name verification
// has already taken place, and therefore fails open).
func (a ACL) VerifyPeerCertificateClient(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return a.cache.verify(verifyRequest{role: roleClient, rawCerts: rawCerts, verifiedChains: verifiedChains, decide: a.verifyClient})
}

// verifyClient is VerifyPeerCertificateClient's decision, with whether it
// may be remembered, on the same terms as verifyServer.
func (a ACL) verifyClient(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (error, bool) {
	if a.PinningEnabled() {
		return a.verifySPKIPin(rawCerts), true
	}

	if len(verifiedChains) == 0 {
		return errors.New("unauthorized: invalid principal, or principal not allowed"), true
	}

	// If the ACL is empty, only hostname verification is performed. The hostname
	// verification happens in crypto/tls itself, so we can skip our checks here.
	if a.empty() {
		return nil, true
	}

	cert := verifiedChains[0][0]

	// Check the subject and SANs against the --verify-* flags.
	if a.matchingRule(cert, &verifyRuleNames) != "" {
		return nil, true
	}

	// Check against OPA
	if a.AllowOPAQuery != nil {
		allowed, cacheable, err := a.evalPolicy(cert)
		if err != nil {
			return err, false
		}
		if allowed {
			return nil, cacheable
		}
		return errors.New("unauthorized: invalid principal, or principal not allowed"), cacheable
	}

	return errors.New("unauthorized: invalid principal, or principal not allowed"), true
}

// Returns true if at least one item from left is also contained in right.
func intersects(left, right []string) bool {
	for _, item := range left {
		if slices.Contains(right, item) {
			return true
		}
	}
	return false
}

// Returns true if at least one item from left is also contained in right.
func intersectsIP(left, right []net.IP) bool {
	for _, l := range left {
		for _, r := range right {
			if r.Equal(l) {
				return true
			}
		}
	}
	return false
}

// Returns true if at least one item from left is also contained in right.
func intersectsURI(left []wildcard.Matcher, right []*url.URL) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	serialized := make([]string, len(right))
	for i, r := range right {
		serialized[i] = r.String()
	}
	for _, l := range left {
		if slices.ContainsFunc(serialized, l.Matches) {
			return true
		}
	}
	return false
}
