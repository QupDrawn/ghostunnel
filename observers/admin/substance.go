package main

// substance.go is the tunnel surface's two substance rules (SPEC 14.3,
// handshake-substance and acl-substance): every member re-judges, from the
// chain the proxy stored under gt/chains/, the CA bundle it stored under
// gt/material/ by the hash the start line (or the last successful reload)
// records, and the policy file on disk the material names, what the proxy
// said it verified and what it said it allowed. The other tunnel rules
// (surface_tunnel.go) hold the proxy to its own account of a connection:
// a handshake line that says verified, an acl line that says allow by
// allow-cn. These two hold the account to the bytes: the chain the client
// presented is verified again against the CA bundle the proxy hashed for
// the material in force at the line, read from the material store by that
// hash and never by its path (a bundle rotated in place by a reload is
// still on record under its old hash for the handshakes before the reload
// and under its new hash for those after), at the handshake's recorded
// time, with the options crypto/tls uses for a client certificate; and
// the rule set the start line records is run again on that chain's leaf,
// each rule kind matched exactly as auth/auth.go matches it, a policy
// evaluated with the same library on the same input. The ring's judgement
// of the data path does not rest on the proxy's honesty about its own
// verification.
//
// Nothing of the proxy is imported: auth.go's matching, the wildcard
// pattern of --allow-uri and the policy loader are mirrored here, and the
// tests in substance_test.go hold the mirror to the original on a matrix
// of leaves and rule sets. Every member carries a byte-identical copy of
// this file; the tunnel member publishes the two identifiers and every
// member computes them for surface-disagree (surfaces.go).
//
// Everything fails closed. A chain the handshake line names that is
// absent, unreadable, does not hash to its name or does not parse; a CA
// bundle the material store lacks under the recorded hash, or holds under
// bytes that do not hash to it, or that holds no certificate; a policy
// file that is absent, unreadable, does not hash to what the trace
// records or does not parse; a rule kind this file cannot
// evaluate (the client-mode rules, a pin with an unknown algorithm, an
// address or pattern that does not parse); a policy that does not compile
// or whose evaluation errs or times out; a verified handshake with no
// chain: each is the check failing with the connection as subject. A
// check that cannot run has not passed.
//
// Cost. Per cycle every referenced chain file, every CA bundle in force
// (from the material store, by hash) and every policy file in force is
// read and hashed once; that is what makes the cache keys content.
// The verdicts are remembered across cycles under those hashes: a chain's
// verification under (chain hash, CA hash) with the window in which the
// verified chain is valid, so a later line whose time falls inside it is
// judged from memory; the rules' verdict on a leaf under (chain hash, rule
// set, the policy hash in force at the line, query), unless the policy
// consulted the clock or the environment, which is never remembered, and
// never under the start line's policy hash alone, since a reload replaces
// the policy the rules run against; a policy's compilation under
// (policy hash, query). No key is a size or a modification time. The cache
// is in-process and is emptied when the boot changes.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	// The SPKI pin algorithms the proxy accepts (auth.go,
	// supportedSPKIPinHashes); crypto/sha512 registers SHA-384 too.
	_ "crypto/sha512"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
)

// The substance identifiers (SPEC 15: constants of the members' own code,
// spelled the same in every copy). Both are the tunnel surface's; the
// subject is the connection id, null when the trace could not be read.
const (
	// checkHandshakeSubstance: every handshake line of the current boot
	// recorded as verified names a chain that this member verifies too,
	// against the CA bundle the proxy stored for the material in force at
	// the handshake's time (or, in pin mode, whose leaf's SPKI hash is one
	// of the pins).
	checkHandshakeSubstance = "handshake-substance"
	// checkACLSubstance: every acl line of the current boot records the
	// decision, and on allow the rule, that the start line's rule set gives
	// this member on the connection's chain.
	checkACLSubstance = "acl-substance"
)

// substanceChainsDir is the directory under the trace root where the proxy
// stores every presented chain, content-addressed: <sha256>.der, the DER of
// every certificate the client presented in presented order, named by the
// lower-case hex SHA-256 of that content.
const substanceChainsDir = "chains"

// substanceMaxChainBytes bounds a chain file (ringtrace/README.md 1.5,
// MaxChainBytes): a file above it is refused by size before any content
// is read, and a read never takes more than it.
const substanceMaxChainBytes = 1 << 20

// substanceMaterialDir is the directory under the trace root where the
// proxy stores the CA bundle it hashed for a start or reload line,
// content-addressed: <sha256>, no suffix, the file's bytes exactly as
// hashed, named by the lower-case hex SHA-256 of that content, which is
// the hash the line's material entry records (ringtrace/README.md 1.6).
const substanceMaterialDir = "material"

// substanceMaxMaterialBytes bounds a material file (ringtrace/README.md
// 1.6, MaxMaterialBytes), as substanceMaxChainBytes bounds a chain file.
const substanceMaxMaterialBytes = 16 << 20

// substanceReChainName is the name of a chain, or of a material file: 64
// lower-case hexadecimal characters, so that a name is never a path.
var substanceReChainName = regexp.MustCompile(`^[0-9a-f]{64}$`)

// substancePolicyTimeout bounds one policy evaluation, as the proxy's
// OPAQueryTimeout bounds its own. A timeout is an evaluation that errs.
const substancePolicyTimeout = 10 * time.Second

// substanceJudge is what the substance rules need beyond the boot: where a
// relative policy path resolves (empty: as given, against the working
// directory; the fixture harness sets it to the fixture's copy; the CA
// bundle is read from the material store by hash and has no path here), the
// proxy's --allow-query (the start line records the policy's hash but not
// the query it is asked, so it is a value to be set, -policy-query, the
// same on every member; empty means a policy rule cannot be re-judged),
// and the cross-cycle memory (nil: nothing remembered).
type substanceJudge struct {
	MaterialBase string
	PolicyQuery  string
	Cache        *substanceCache
}

// substanceJudgeFor is the judge a cycle runs with: the configuration's
// values and the memory kept in State, allocated on first use.
func substanceJudgeFor(cfg *Config, st *State) substanceJudge {
	if st.Substance == nil {
		st.Substance = &substanceCache{}
	}
	return substanceJudge{MaterialBase: cfg.MaterialBase, PolicyQuery: cfg.PolicyQuery, Cache: st.Substance}
}

// substanceCache is the cross-cycle memory. Every key is a content hash,
// or content hashes joined; the boot number resets it.
type substanceCache struct {
	Boot int64
	// chains: (chain hash, CA hash) -> the window in which the chain
	// verified.
	chains map[string]substanceWindow
	// refused: (chain hash, CA hash, the recorded second) -> the chain did
	// not verify at that time. The proxy's own VerifyCache judges a
	// refusal again because a refused client may return with a different
	// chain; here every input is a content hash or a recorded second and
	// the answer cannot change within the boot.
	refused map[string]struct{}
	// certs: chain hash -> the certificates parsed from bytes that hashed
	// to it. Used only after this cycle's read hashed the same.
	certs map[string][]*x509.Certificate
	// pools: CA hash -> the pool built from bytes that hashed to it.
	pools map[string]*x509.CertPool
	// rules: (chain hash, rule set, policy hash, query) -> the rule the
	// leaf matched, "" for none. Not written when a policy's evaluation
	// consulted the clock or the environment.
	rules map[string]string
	// policies: (policy hash, query) -> the compiled policy or the error
	// compiling it, which is a function of the bytes.
	policies map[string]*substancePolicy
}

type substanceWindow struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type substancePolicy struct {
	query *rego.PreparedEvalQuery
	err   error
}

func (c *substanceCache) reset(boot int64) {
	if c.chains != nil && c.Boot == boot {
		return
	}
	c.Boot = boot
	c.chains = map[string]substanceWindow{}
	c.refused = map[string]struct{}{}
	c.certs = map[string][]*x509.Certificate{}
	c.pools = map[string]*x509.CertPool{}
	c.rules = map[string]string{}
	c.policies = map[string]*substancePolicy{}
}

// substanceRules is the start line's rule set as this file evaluates it,
// mirroring what ring.go's aclRules wrote from the ACL the verifier
// applies (ringtrace/README.md 1.2) and how auth.go applies it.
type substanceRules struct {
	// set is the rule set as recorded, joined, the cache key's part.
	set string
	// disableAuth: the set is exactly disable-authentication, the server
	// asks for no certificate and every connection is allowed under that
	// rule (ring.go, Handshake) without verification.
	disableAuth bool
	// pins: pin mode (auth.go, PinningEnabled): the leaf's SPKI hash is
	// compared with each pin and nothing else is verified or matched.
	pins []substancePin
	// allowAll: every verified chain is allowed (auth.go, AllowAll).
	allowAll       bool
	cns, ous, dnss []string
	ips            []net.IP
	uris           []*regexp.Regexp
	// policy is the policy file's hash the set names, "" when none.
	policy string
	// unknown lists the entries this file cannot evaluate: the client-mode
	// rules, disable-authentication beside anything, a pin, an address or
	// a pattern that does not parse. Non-empty fails acl-substance.
	unknown []string
}

type substancePin struct {
	hash   crypto.Hash
	digest []byte
}

// substanceParseRules classifies each entry of the recorded set exactly
// as gtACLRuleValid admits it: a bare token, or a prefix and its value.
func substanceParseRules(set []string) *substanceRules {
	r := &substanceRules{set: strings.Join(set, ",")}
	if len(set) == 1 && set[0] == "disable-authentication" {
		r.disableAuth = true
		return r
	}
	for _, rule := range set {
		prefix, value, _ := strings.Cut(rule, ":")
		switch prefix {
		case "allow-all":
			r.allowAll = true
		case "allow-cn":
			r.cns = append(r.cns, value)
		case "allow-ou":
			r.ous = append(r.ous, value)
		case "allow-dns":
			r.dnss = append(r.dnss, value)
		case "allow-ip":
			ip := net.ParseIP(value)
			if ip == nil {
				r.unknown = append(r.unknown, rule)
				continue
			}
			r.ips = append(r.ips, ip)
		case "allow-uri":
			re, err := substanceCompileWildcard(value)
			if err != nil {
				r.unknown = append(r.unknown, rule)
				continue
			}
			r.uris = append(r.uris, re)
		case "allow-spki-pin":
			pin, err := substanceParsePin(value)
			if err != nil {
				r.unknown = append(r.unknown, rule)
				continue
			}
			r.pins = append(r.pins, pin)
		case "policy":
			r.policy = value
		default:
			r.unknown = append(r.unknown, rule)
		}
	}
	return r
}

// substanceParsePin parses the start line's pin form, <algo>:<hex-digest>
// (auth.go, SPKIPin.String), with the algorithms auth.go supports.
func substanceParsePin(s string) (substancePin, error) {
	algo, digest, ok := strings.Cut(s, ":")
	if !ok {
		return substancePin{}, errors.New("pin is not <algo>:<hex-digest>")
	}
	var h crypto.Hash
	switch strings.ToLower(algo) {
	case "sha256":
		h = crypto.SHA256
	case "sha384":
		h = crypto.SHA384
	case "sha512":
		h = crypto.SHA512
	default:
		return substancePin{}, fmt.Errorf("unsupported pin algorithm %q", algo)
	}
	if !h.Available() {
		return substancePin{}, fmt.Errorf("pin algorithm %q is not linked in", algo)
	}
	raw, err := hex.DecodeString(digest)
	if err != nil {
		return substancePin{}, err
	}
	if len(raw) != h.Size() {
		return substancePin{}, fmt.Errorf("pin digest is %d bytes, not %d", len(raw), h.Size())
	}
	return substancePin{hash: h, digest: raw}, nil
}

// substanceCompileWildcard is wildcard.CompileWithSeparator(pattern, '/')
// (wildcard/matcher.go), the matcher --allow-uri patterns compile to, as a
// regular expression: a '*' segment matches one segment, a trailing '**'
// matches the rest, a bare '**' matches anything, a single trailing
// separator is dropped and the final separator is optional on the input.
func substanceCompileWildcard(pattern string) (*regexp.Regexp, error) {
	const sep = "/"
	if pattern == "" {
		return nil, errors.New("input pattern was empty string")
	}
	if len(pattern) > len(sep) && strings.HasSuffix(pattern, sep) {
		pattern = pattern[:len(pattern)-len(sep)]
	}
	if pattern == "**" {
		return regexp.Compile("^.*$")
	}
	segments := strings.Split(pattern, sep)
	sepOutside := regexp.QuoteMeta(sep)
	sepInsideClass := fmt.Sprintf(`\x{%X}`, '/')
	var re bytes.Buffer
	re.WriteString("^")
loop:
	for i, segment := range segments {
		switch segment {
		case "*":
			re.WriteString("[^")
			re.WriteString(sepInsideClass)
			re.WriteString("]+")
		case "**":
			if i != len(segments)-1 {
				return nil, errors.New("wildcard '**' can only appear at end of pattern")
			}
			re.WriteString("?(|")
			re.WriteString(sepOutside)
			re.WriteString(".*)$")
			break loop
		default:
			if strings.Contains(segment, "*") {
				return nil, errors.New("wildcard '*' can only appear between two separators")
			}
			re.WriteString(regexp.QuoteMeta(segment))
		}
		re.WriteString(sepOutside)
		if i == len(segments)-1 {
			re.WriteString("?$")
		}
	}
	return regexp.Compile(re.String())
}

// matchingRule is auth.go's matchingRule with prefix "allow": the first of
// cn, ou, dns, ip, uri whose list meets the leaf, or "".
func (r *substanceRules) matchingRule(leaf *x509.Certificate) string {
	for _, cn := range r.cns {
		if cn == leaf.Subject.CommonName {
			return "allow-cn"
		}
	}
	if substanceIntersects(r.ous, leaf.Subject.OrganizationalUnit) {
		return "allow-ou"
	}
	if substanceIntersects(r.dnss, leaf.DNSNames) {
		return "allow-dns"
	}
	for _, l := range r.ips {
		for _, c := range leaf.IPAddresses {
			if c.Equal(l) {
				return "allow-ip"
			}
		}
	}
	if len(r.uris) > 0 && len(leaf.URIs) > 0 {
		serialized := make([]string, len(leaf.URIs))
		for i, u := range leaf.URIs {
			serialized[i] = u.String()
		}
		for _, re := range r.uris {
			for _, s := range serialized {
				if re.MatchString(s) {
					return "allow-uri"
				}
			}
		}
	}
	return ""
}

func substanceIntersects(left, right []string) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}
	return false
}

// pinned is auth.go's verifySPKIPin on the leaf.
func (r *substanceRules) pinned(leaf *x509.Certificate) bool {
	for _, pin := range r.pins {
		h := pin.hash.New()
		h.Write(leaf.RawSubjectPublicKeyInfo)
		if bytes.Equal(h.Sum(nil), pin.digest) {
			return true
		}
	}
	return false
}

// ---- files ----

// substancePath resolves a material path: absolute as given, relative
// against the base when there is one.
func substancePath(base, p string) string {
	if base != "" && !filepath.IsAbs(p) {
		return filepath.Join(base, p)
	}
	return p
}

// substanceReadMaterial reads a file the material names on disk (the
// policy) whole, under the read retry of this build, as the proxy reads
// it (os.ReadFile: a symbolic link is followed). What it hashes to is the
// caller's to judge. The CA bundle is not read this way: it comes from
// the material store, by hash (ca).
func substanceReadMaterial(p string) ([]byte, error) {
	return readFile(p)
}

// substanceReadStored reads a content-addressed file of the proxy's
// stores, gt/chains/<name>.der or gt/material/<name>, by the reader's
// rules of ringtrace/README.md 1.5 and 1.6, the proxy's own ReadChain and
// ReadMaterial mirrored and not shared: the file exists and is a regular
// file as Lstat sees it (a symbolic link is judged as the link and
// refused, a directory is refused; a <name>.tmp is never opened, so a
// file that only has its .tmp is absent); its size is at most max,
// checked before any content is read, and the read is bounded by it; and
// the content's SHA-256 is the name. The file opened is held to be the one
// Lstat judged. Nothing is returned with an error. The name's shape is
// the caller's (chain, ca). Under the read retry of this build, since a
// stored file is renamed into place as it may be opened.
func substanceReadStored(p, name string, max int64) ([]byte, error) {
	var data []byte
	err := readRetrying(func() error {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("stored %s: not a regular file", name)
		}
		if info.Size() > max {
			return fmt.Errorf("stored %s: %d bytes exceeds the bound", name, info.Size())
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil {
			return err
		}
		if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			return fmt.Errorf("stored %s: the file opened is not the one judged", name)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(io.LimitReader(f, max+1)); err != nil {
			return err
		}
		if int64(buf.Len()) > max {
			return fmt.Errorf("stored %s: exceeds the bound", name)
		}
		data = buf.Bytes()
		return nil
	})
	if err != nil {
		return nil, err
	}
	if substanceHash(data) != name {
		return nil, fmt.Errorf("stored %s: the content does not hash to the name", name)
	}
	return data, nil
}

func substanceHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// substanceCycle is one cycle's reads, so that a chain, a CA bundle or a
// policy file referenced by many lines is read and hashed once per cycle:
// chains and cas by the hash a line records, files by path.
type substanceCycle struct {
	judge  substanceJudge
	root   string
	cache  *substanceCache
	chains map[string]*substanceChain
	cas    map[string]*substanceCA
	files  map[string]*substanceFile
	// ruleSuffix is the rules' memory key after the chain hash for the
	// rule set ruleSet and the policy hash rulePolicy (ruleSuffixFor):
	// the query does not change within a cycle and the set does not
	// change within a boot, so it is rebuilt only when a reload changes
	// the policy in force (or a caller judges another set on one cycle,
	// as the differential test does).
	ruleSuffix, ruleSet, rulePolicy string
	ruleSuffixSet                   bool
}

// ruleSuffixFor is the rules' memory key after the chain hash: NUL, the
// rule set as recorded, NUL, the hash of the policy in force at the line
// (substancePolicyInForce), NUL, the query. Built once per cycle per
// (rule set, policy in force).
func (cy *substanceCycle) ruleSuffixFor(r *substanceRules, mat substanceMaterial) string {
	policy := substancePolicyInForce(mat)
	if !cy.ruleSuffixSet || cy.ruleSet != r.set || cy.rulePolicy != policy {
		cy.ruleSuffix = "\x00" + r.set + "\x00" + policy + "\x00" + cy.judge.PolicyQuery
		cy.ruleSet, cy.rulePolicy, cy.ruleSuffixSet = r.set, policy, true
	}
	return cy.ruleSuffix
}

// substanceChain is one chain file as read this cycle: its certificates
// when the bytes hashed to the name and parsed, else nil.
type substanceChain struct {
	hash  string
	certs []*x509.Certificate
	// The memory keys this chain is judged under, built once per cycle
	// rather than once per line: key is (chain hash, CA hash) under
	// keyCA (verified), ruleKey is the rules' key under ruleSuffix
	// (leafRule). A chain judged under another CA or another material
	// rebuilds them; the keys' content is unchanged.
	keyCA, key          string
	ruleSuffix, ruleKey string
}

// verifyKey is the verification memory's key for this chain under the
// bundle hashed to caHash: <chain hash>:<CA hash>.
func (c *substanceChain) verifyKey(caHash string) string {
	if c.key == "" || c.keyCA != caHash {
		c.keyCA, c.key = caHash, c.hash+":"+caHash
	}
	return c.key
}

// rulesKey is the rules' memory key for this chain under the suffix
// (the rule set, the policy in force and the query, NUL-joined; see
// substanceCycle.ruleSuffixFor): <chain hash><suffix>.
func (c *substanceChain) rulesKey(suffix string) string {
	if c.ruleKey == "" || c.ruleSuffix != suffix {
		c.ruleSuffix, c.ruleKey = suffix, c.hash+suffix
	}
	return c.ruleKey
}

// substanceCA is one CA bundle as read this cycle from the material
// store: its pool when the bytes hashed to the recorded hash and held a
// certificate, else nil.
type substanceCA struct {
	hash string
	pool *x509.CertPool
}

// substanceFile is one file read this cycle, hashed.
type substanceFile struct {
	hash string
	data []byte
	err  error
}

func (cy *substanceCycle) file(p string) *substanceFile {
	if f, ok := cy.files[p]; ok {
		return f
	}
	f := &substanceFile{}
	f.data, f.err = substanceReadMaterial(p)
	if f.err == nil {
		f.hash = substanceHash(f.data)
	}
	cy.files[p] = f
	return f
}

// chain reads gt/chains/<hash>.der by the reader's rules (substanceReadChain,
// after the name's shape) and parses it as a concatenation of at least one
// DER certificate; certs is nil on any refusal. The parse is remembered
// under the hash, which the bytes read this cycle were held to.
func (cy *substanceCycle) chain(hash string) *substanceChain {
	if c, ok := cy.chains[hash]; ok {
		return c
	}
	c := &substanceChain{hash: hash}
	cy.chains[hash] = c
	if !substanceReChainName.MatchString(hash) {
		return c
	}
	data, err := substanceReadStored(filepath.Join(cy.root, substanceChainsDir, hash+".der"), hash, substanceMaxChainBytes)
	if err != nil {
		return c
	}
	if certs, ok := cy.cache.certs[hash]; ok {
		c.certs = certs
		return c
	}
	certs, err := x509.ParseCertificates(data)
	if err != nil || len(certs) == 0 {
		return c
	}
	c.certs = certs
	cy.cache.certs[hash] = certs
	return c
}

// ca reads the CA bundle a material entry names from the material store
// under the trace root, by the recorded hash and never by the path: the
// bytes the proxy hashed for the line, which are what it verified against,
// whatever the file at the path holds now. A bundle with no path (the
// system trust store) or no hash cannot be judged; a hash the store lacks,
// or holds under bytes that do not hash to it, or whose bytes hold no
// certificate, cannot be judged either, and a check that cannot run has
// not passed. The read is remembered for the cycle under the hash: two
// entries that record one hash read it once, and two that record
// different hashes, at one path or two, never answer for each other.
func (cy *substanceCycle) ca(m *gtMaterial) *substanceCA {
	if m == nil || m.Path == "" || m.SHA256 == nil {
		return &substanceCA{}
	}
	hash := *m.SHA256
	if c, ok := cy.cas[hash]; ok {
		return c
	}
	c := &substanceCA{}
	cy.cas[hash] = c
	if !substanceReChainName.MatchString(hash) {
		return c
	}
	data, err := substanceReadStored(filepath.Join(cy.root, substanceMaterialDir, hash), hash, substanceMaxMaterialBytes)
	if err != nil {
		return c
	}
	c.hash = hash
	if pool, ok := cy.cache.pools[hash]; ok {
		c.pool = pool
		return c
	}
	// certloader.LoadTrustStore: a new pool, every PEM certificate in the
	// bundle appended, and at least one (ErrNoCACerts otherwise).
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return c
	}
	c.pool = pool
	cy.cache.pools[hash] = pool
	return c
}

// verified reports whether the chain verifies against the CA at the given
// time, as the proxy's verifier does (auth.go, clientChainVerifier.verify,
// the options crypto/tls uses under RequireAndVerifyClientCert): roots the
// bundle, intermediates every presented certificate after the leaf, key
// usage client authentication, the recorded time. A verification is
// remembered under (chain hash, CA hash) with the window in which every
// certificate of the verified chain is valid; a later time inside it is
// answered from memory. A refusal is remembered under (chain hash, CA
// hash, the recorded second): the same bytes against the same bundle at
// the same time verify the same way every cycle, so a line the ring has
// once refused is refused from memory for the rest of the boot rather
// than verified again on each of them. Both memories are content keys
// that empty when the boot changes.
func (cy *substanceCycle) verified(c *substanceChain, ca *substanceCA, at time.Time) bool {
	if c == nil || c.certs == nil || ca == nil || ca.pool == nil {
		return false
	}
	key := c.verifyKey(ca.hash)
	if w, ok := cy.cache.chains[key]; ok && !at.Before(w.NotBefore) && !at.After(w.NotAfter) {
		return true
	}
	rkey := key + ":" + strconv.FormatInt(at.Unix(), 10)
	if _, ok := cy.cache.refused[rkey]; ok {
		return false
	}
	opts := x509.VerifyOptions{
		Roots:         ca.pool,
		CurrentTime:   at,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, cert := range c.certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	chains, err := c.certs[0].Verify(opts)
	if err != nil || len(chains) == 0 || len(chains[0]) == 0 {
		cy.cache.refused[rkey] = struct{}{}
		return false
	}
	w := substanceWindow{NotBefore: chains[0][0].NotBefore, NotAfter: chains[0][0].NotAfter}
	for _, cert := range chains[0][1:] {
		if cert.NotBefore.After(w.NotBefore) {
			w.NotBefore = cert.NotBefore
		}
		if cert.NotAfter.Before(w.NotAfter) {
			w.NotAfter = cert.NotAfter
		}
	}
	cy.cache.chains[key] = w
	return true
}

// ---- the policy ----

// policy compiles the policy file a material entry names, held to the hash
// the rule set records, with the query this member was given, exactly as
// the proxy loads it (policy/loader.go): a .rego file is parsed as a Rego
// v0 module with annotations processed, as rego.Load parses it, from the
// bytes that were hashed; any other path is a bundle, loaded by
// rego.LoadBundle from the path after the file was hashed. The compiled
// query is remembered under (policy hash, query), and so is a compilation
// that failed, which is a function of the bytes.
func (cy *substanceCycle) policy(m *gtMaterial, hash string) (*rego.PreparedEvalQuery, error) {
	query := cy.judge.PolicyQuery
	if query == "" {
		return nil, errors.New("no policy query configured (-policy-query)")
	}
	if m == nil || m.Path == "" || m.SHA256 == nil {
		return nil, errors.New("the policy material names no file or no hash")
	}
	if *m.SHA256 != hash {
		return nil, errors.New("the policy material's hash is not the rule set's")
	}
	p := substancePath(cy.judge.MaterialBase, m.Path)
	f := cy.file(p)
	if f.err != nil {
		return nil, f.err
	}
	if f.hash != hash {
		return nil, errors.New("the policy file on disk does not hash to the recorded hash")
	}
	key := hash + ":" + query
	if pol, ok := cy.cache.policies[key]; ok {
		return pol.query, pol.err
	}
	pol := &substancePolicy{}
	cy.cache.policies[key] = pol
	ctx, cancel := context.WithTimeout(context.Background(), substancePolicyTimeout)
	defer cancel()
	var r *rego.Rego
	if strings.HasSuffix(p, ".rego") {
		mod, err := ast.ParseModuleWithOpts(p, string(f.data), ast.ParserOptions{RegoVersion: ast.RegoV0, ProcessAnnotation: true})
		if err != nil {
			pol.err = err
			return nil, err
		}
		r = rego.New(rego.Query(query), rego.ParsedModule(mod), rego.SetRegoVersion(ast.RegoV0))
	} else {
		r = rego.New(rego.Query(query), rego.LoadBundle(p))
	}
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		pol.err = err
		return nil, err
	}
	pol.query = &pq
	return pol.query, nil
}

// substanceClockSensitive are the builtins auth.go's clockTracer treats as
// consulting the clock although OPA does not mark them non-deterministic.
var substanceClockSensitive = map[string]bool{
	"io.jwt.decode_verify":                                   true,
	"crypto.x509.parse_and_verify_certificates":              true,
	"crypto.x509.parse_and_verify_certificates_with_options": true,
}

// substanceClockTracer is auth.go's clockTracer: it watches one evaluation
// for a call to a builtin whose result is not a function of the input and
// the policy, whose decision is then not remembered.
type substanceClockTracer struct {
	sensitive bool
}

func (t *substanceClockTracer) Enabled() bool { return !t.sensitive }

func (t *substanceClockTracer) Config() topdown.TraceConfig { return topdown.TraceConfig{} }

func (t *substanceClockTracer) TraceEvent(event topdown.Event) {
	if t.sensitive || event.Op != topdown.EvalOp {
		return
	}
	expr, ok := event.Node.(*ast.Expr)
	if !ok || !expr.IsCall() {
		return
	}
	name := expr.Operator().String()
	if substanceClockSensitive[name] {
		t.sensitive = true
		return
	}
	if builtin := ast.BuiltinMap[name]; builtin != nil && builtin.Nondeterministic {
		t.sensitive = true
	}
}

// evalPolicy is auth.go's evalPolicy: the query on the input
// {"certificate": leaf}, allowed when the result set says so.
func substanceEvalPolicy(pq *rego.PreparedEvalQuery, leaf *x509.Certificate) (allowed, cacheable bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), substancePolicyTimeout)
	defer cancel()
	input := map[string]any{"certificate": leaf}
	tracer := &substanceClockTracer{}
	results, err := pq.Eval(ctx, rego.EvalInput(input), rego.EvalQueryTracer(tracer))
	if err != nil {
		return false, false, err
	}
	return results.Allowed(), !tracer.sensitive, nil
}

// ---- the judgement ----

// substanceMaterial is the trust material in force at a line: the start
// line's list, then each successful reload's entries replacing it per
// kind. A failed reload changes nothing: the proxy keeps serving on, or
// refuses on, the material it had.
type substanceMaterial map[string]*gtMaterial

func (m substanceMaterial) apply(ms []gtMaterial) {
	for i := range ms {
		entry := ms[i]
		m[entry.Material] = &entry
	}
}

// substancePolicyInForce is the hash of the policy file in force under the
// material: the entry's recorded hash, or "" when the material names no
// policy or no hash for it.
func substancePolicyInForce(mat substanceMaterial) string {
	if m := mat["policy"]; m != nil && m.SHA256 != nil {
		return *m.SHA256
	}
	return ""
}

// leafRule is the rule the leaf matches under the set, the rules alone
// (not the chain, not the pins): auth.go's matchingRule, then the policy.
// Remembered under (chain hash, rule set, the policy hash in force at the
// line, query) unless the policy consulted the clock or the environment.
// The hash in the key is the material's at the line being judged, never
// the start line's alone: a reload that brings another policy starts a
// fresh memory for every chain, so a verdict reached under the policy
// before the reload never answers for a line after it. The key's parts
// after the chain hash are built once per cycle per policy in force
// (ruleSuffixFor) and the key once per chain per cycle (rulesKey).
func (cy *substanceCycle) leafRule(r *substanceRules, c *substanceChain, leaf *x509.Certificate, mat substanceMaterial) (string, error) {
	key := c.rulesKey(cy.ruleSuffixFor(r, mat))
	if rule, ok := cy.cache.rules[key]; ok {
		return rule, nil
	}
	rule := r.matchingRule(leaf)
	cacheable := true
	if rule == "" && r.policy != "" {
		pq, err := cy.policy(mat["policy"], r.policy)
		if err != nil {
			return "", err
		}
		allowed, c, err := substanceEvalPolicy(pq, leaf)
		if err != nil {
			return "", err
		}
		cacheable = c
		if allowed {
			rule = "policy"
		}
	}
	if cacheable {
		cy.cache.rules[key] = rule
	}
	return rule, nil
}

// decide is auth.go's verifyServer and ServerRule together, on the
// connection's chain (nil when the client presented none): the decision
// and, on allow, the rule name ring.go records; an error when the set
// holds a rule this file cannot evaluate or the policy could not run.
func (cy *substanceCycle) decide(r *substanceRules, c *substanceChain, mat substanceMaterial, at time.Time) (decision, rule string, err error) {
	if len(r.unknown) > 0 {
		return "", "", fmt.Errorf("rule %q cannot be evaluated", r.unknown[0])
	}
	if r.disableAuth {
		return "allow", "disable-authentication", nil
	}
	if c == nil || c.certs == nil {
		return "deny", "none", nil
	}
	leaf := c.certs[0]
	if len(r.pins) > 0 {
		if r.pinned(leaf) {
			return "allow", "allow-spki-pin", nil
		}
		return "deny", "none", nil
	}
	if !cy.verified(c, cy.ca(mat["ca"]), at) {
		return "deny", "none", nil
	}
	if r.allowAll {
		return "allow", "allow-all", nil
	}
	matched, err := cy.leafRule(r, c, leaf, mat)
	if err != nil {
		return "", "", err
	}
	if matched != "" {
		return "allow", matched, nil
	}
	return "deny", "none", nil
}

// substanceACMEProbeRule is the rule ring.go records on the denial of a
// TLS-ALPN-01 challenge probe: a handshake that negotiated acme-tls/1
// completes with no certificate asked for and is denied before any rule
// runs, whatever the rule set.
const substanceACMEProbeRule = "acme-tls/1"

// substanceFindings judges a readable current boot with a start line by
// the two substance rules. Each failing connection is one finding per
// rule: the handshake-substance findings in the order of the handshake
// lines, then the acl-substance findings in the order of the acl lines.
//
// The lines of a connection are paired by conn, not by their order: the
// proxy writes a connection's handshake before its acl, but the rule is
// about the handshake line of the same conn wherever it lies, and
// conn-consistent (surface_tunnel.go) is what judges the count of each.
// A connection's first handshake line is the one paired.
func substanceFindings(boot *gtBoot, j substanceJudge) []Finding {
	if j.Cache == nil {
		j.Cache = &substanceCache{}
	}
	j.Cache.reset(boot.Number)
	cy := &substanceCycle{judge: j, root: boot.Root, cache: j.Cache, chains: map[string]*substanceChain{}, cas: map[string]*substanceCA{}, files: map[string]*substanceFile{}}
	start := boot.Records[0].Start
	rules := substanceParseRules(start.Config.ACL)
	server := start.Config.Mode == "server"

	// One walk in sequence order: the material in force at each line,
	// each connection's first handshake line with the material of its
	// time, and every acl line. The material map is replaced, never
	// changed, on a reload, so a handshake holds the map of its time
	// without a copy per line.
	mat := substanceMaterial{}
	mat.apply(start.Config.Material)
	type judged struct {
		record   *gtRecord
		material substanceMaterial
	}
	handshakes := map[int64]judged{}
	var acls []*gtRecord
	var out []Finding
	seen := map[Finding]bool{}
	fail := func(check string, conn int64) {
		f := Finding{Check: check, Subject: strconv.FormatInt(conn, 10)}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for i := range boot.Records {
		rec := &boot.Records[i]
		switch rec.Kind {
		case "reload":
			if rec.Reload.Outcome == "ok" && len(rec.Reload.Material) > 0 {
				next := substanceMaterial{}
				for k, v := range mat {
					next[k] = v
				}
				next.apply(rec.Reload.Material)
				mat = next
			}
		case "handshake":
			hs := rec.Handshake
			if _, ok := handshakes[hs.Conn]; !ok {
				handshakes[hs.Conn] = judged{record: rec, material: mat}
			}
			if !hs.Verified {
				continue
			}
			// handshake-substance: the proxy says it verified; so must
			// this member, from the chain and the CA bundle the proxy
			// stored for the material in force (or the pins). Client
			// mode is not mirrored (the server's chain is
			// verified against a server name the trace does not carry),
			// nor is a rule set with an entry this file cannot read: a
			// check that cannot run has not passed.
			if !server || hs.Chain == "" || len(rules.unknown) > 0 {
				fail(checkHandshakeSubstance, hs.Conn)
				continue
			}
			c := cy.chain(hs.Chain)
			if c.certs == nil {
				fail(checkHandshakeSubstance, hs.Conn)
				continue
			}
			if len(rules.pins) > 0 {
				if !rules.pinned(c.certs[0]) {
					fail(checkHandshakeSubstance, hs.Conn)
				}
				continue
			}
			if !cy.verified(c, cy.ca(mat["ca"]), rec.At) {
				fail(checkHandshakeSubstance, hs.Conn)
			}
		case "acl":
			acls = append(acls, rec)
		}
	}

	// acl-substance: the rule set re-run on the connection's chain must
	// give the recorded decision, and on allow the recorded rule. A deny
	// this member would allow is a finding as much as an allow it would
	// deny.
	for _, rec := range acls {
		a := rec.ACL
		hs, ok := handshakes[a.Conn]
		if !ok || !server {
			fail(checkACLSubstance, a.Conn)
			continue
		}
		h := hs.record.Handshake
		if a.Decision == "deny" && a.Rule == substanceACMEProbeRule && !h.Verified && h.Chain == "" {
			// The challenge probe's denial (ring.go, Handshake): denied
			// before any rule runs, no certificate asked for. The ALPN
			// is not in the trace, so what is held is what the trace
			// does carry: nothing verified, nothing presented, denied.
			continue
		}
		var c *substanceChain
		if h.Chain != "" {
			c = cy.chain(h.Chain)
			if c.certs == nil {
				fail(checkACLSubstance, a.Conn)
				continue
			}
		}
		decision, rule, err := cy.decide(rules, c, hs.material, hs.record.At)
		if err != nil || decision != a.Decision || (decision == "allow" && rule != a.Rule) {
			fail(checkACLSubstance, a.Conn)
		}
	}
	return out
}
