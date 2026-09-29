package main

// substance_diff_test.go holds the mirror in substance.go to the original:
// the proxy's auth.ACL (auth/auth.go), imported here and nowhere else in
// the members (the members import nothing of the proxy at runtime; a test
// may). On a matrix of leaves and rule sets the mirror's decision and rule
// must equal what the proxy's verifier decides and what ServerRule names;
// on a matrix of chains and times the mirror's verification must equal
// crypto/x509 with the options the proxy's chain verifier uses; and in pin
// mode the mirror's pin check must equal the proxy's; a policy file, as a
// .rego module or as a bundle, compiled by the mirror from the bytes it
// hashed must decide as the proxy's policy.Prepare does on those bytes,
// whatever the file holds by the time it is compiled. The recorded form
// of each rule set is built here as ring.go's aclRules builds it (sorted,
// prefix:value, the policy by its file's hash). Every member carries a
// byte-identical copy of this file.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/wildcard"
	"github.com/open-policy-agent/opa/v1/rego"
)

// diffPolicy allows three shapes of leaf, so that the policy's decision
// varies across the matrix and does not coincide with one flag's.
const diffPolicy = `package policy

default allow = false

allow {
	input.certificate.Subject.CommonName == "client.example"
}

allow {
	input.certificate.Subject.OrganizationalUnit[_] == "dev"
}

allow {
	input.certificate.DNSNames[_] == "b.example"
}
`

const diffQuery = "data.policy.allow"

// diffRuleSet is one rule set both as the proxy's ACL and as the start
// line records it.
type diffRuleSet struct {
	name     string
	recorded []string
	acl      auth.ACL
}

// diffPKI is the test's PKI: a root, an intermediate and a policy file
// on disk, the material map the mirror judges under, and a trace root
// whose material store holds the CA bundle under the map's hash, as the
// proxy's does.
type diffPKI struct {
	root, inter *subEntity
	mat         substanceMaterial
	caPath      string
	policyHash  string
	policyPath  string
	store       string
}

func diffMint(t testing.TB) *diffPKI {
	t.Helper()
	from, until := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	root := subIssue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Diff CA"}, NotBefore: from, NotAfter: until, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	inter := subIssue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Diff Intermediate"}, NotBefore: from, NotAfter: until, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}, root)
	dir := t.TempDir()
	subWriteCA(t, dir, root)
	caPath := filepath.Join(dir, "ca.pem")
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(policyPath, []byte(diffPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	caHash, policyHash := substanceHash(caBytes), substanceHash([]byte(diffPolicy))
	mat := substanceMaterial{
		"ca":     &gtMaterial{Material: "ca", Path: caPath, SHA256: &caHash},
		"policy": &gtMaterial{Material: "policy", Path: policyPath, SHA256: &policyHash},
	}
	store := t.TempDir()
	subStoreMaterial(t, store, caBytes)
	return &diffPKI{root: root, inter: inter, mat: mat, caPath: caPath, policyHash: policyHash, policyPath: policyPath, store: store}
}

// diffLeaf issues a client leaf under the intermediate.
func (p *diffPKI) diffLeaf(t testing.TB, cn string, ous, dns []string, ips []net.IP, uris []*url.URL) *subEntity {
	t.Helper()
	return subIssue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    dns,
		IPAddresses: ips,
		URIs:        uris,
	}, p.inter)
}

// diffLeaves is the leaf matrix: every combination of three values of
// each of CN, OU, DNS, IP and URI, so that each rule kind meets leaves
// that carry none, one and several of the values, including the ones the
// rule sets name and ones they do not.
func (p *diffPKI) diffLeaves(t testing.TB) []*subEntity {
	t.Helper()
	uri := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	cns := []string{"client.example", "other.example", ""}
	ous := [][]string{nil, {"ops"}, {"dev", "ops"}}
	dnss := [][]string{nil, {"a.example"}, {"a.example", "b.example"}}
	ips := [][]net.IP{nil, {net.ParseIP("10.0.0.7")}, {net.ParseIP("192.0.2.9"), net.ParseIP("::1")}}
	uris := [][]*url.URL{nil, {uri("spiffe://example.org/ns/prod/sa/client")}, {uri("spiffe://example.org/ns/dev/sa/x"), uri("https://other.org/p/q/")}}
	var out []*subEntity
	for _, cn := range cns {
		for _, ou := range ous {
			for _, dns := range dnss {
				for _, ip := range ips {
					for _, u := range uris {
						out = append(out, p.diffLeaf(t, cn, ou, dns, ip, u))
					}
				}
			}
		}
	}
	return out
}

// diffRecord is ring.go's aclRules for a server ACL: each value under its
// prefix, allow-all alone, policy:<hash> when a policy is in force,
// sorted and without duplicates.
func diffRecord(acl auth.ACL, uris []string, policyHash string) []string {
	var out []string
	switch {
	case acl.PinningEnabled():
		for _, pin := range acl.AllowedPins {
			out = append(out, "allow-spki-pin:"+pin.String())
		}
	case acl.AllowAll:
		out = append(out, "allow-all")
	default:
		for _, cn := range acl.AllowedCNs {
			out = append(out, "allow-cn:"+cn)
		}
		for _, ou := range acl.AllowedOUs {
			out = append(out, "allow-ou:"+ou)
		}
		for _, dns := range acl.AllowedDNSs {
			out = append(out, "allow-dns:"+dns)
		}
		for _, ip := range acl.AllowedIPs {
			out = append(out, "allow-ip:"+ip.String())
		}
		for _, uri := range uris {
			out = append(out, "allow-uri:"+uri)
		}
		if acl.AllowOPAQuery != nil {
			out = append(out, "policy:"+policyHash)
		}
	}
	sort.Strings(out)
	return out
}

// diffRuleSets is the rule-set matrix: each kind alone with one and with
// several values (matching and not), combinations, allow-all, the policy
// alone and beside flags.
func (p *diffPKI) diffRuleSets(t testing.TB) []diffRuleSet {
	t.Helper()
	pol, err := policy.LoadFromPath(p.policyPath, diffQuery)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name string, acl auth.ACL, uris ...string) diffRuleSet {
		if len(uris) > 0 {
			ms, err := wildcard.CompileList(uris)
			if err != nil {
				t.Fatal(err)
			}
			acl.AllowedURIs = ms
		}
		acl.OPAQueryTimeout = 10 * time.Second
		return diffRuleSet{name: name, recorded: diffRecord(acl, uris, p.policyHash), acl: acl}
	}
	return []diffRuleSet{
		mk("all", auth.ACL{AllowAll: true}),
		mk("cn", auth.ACL{AllowedCNs: []string{"client.example"}}),
		mk("cn2", auth.ACL{AllowedCNs: []string{"other.example", "nobody.example"}}),
		mk("ou", auth.ACL{AllowedOUs: []string{"ops"}}),
		mk("ou2", auth.ACL{AllowedOUs: []string{"dev", "qa"}}),
		mk("dns", auth.ACL{AllowedDNSs: []string{"a.example"}}),
		mk("dns2", auth.ACL{AllowedDNSs: []string{"b.example", "c.example"}}),
		mk("ip", auth.ACL{AllowedIPs: []net.IP{net.ParseIP("10.0.0.7")}}),
		mk("ip2", auth.ACL{AllowedIPs: []net.IP{net.ParseIP("::1"), net.ParseIP("192.0.2.9")}}),
		mk("uri", auth.ACL{}, "spiffe://example.org/ns/prod/sa/client"),
		mk("uri-star", auth.ACL{}, "spiffe://example.org/ns/*/sa/*"),
		mk("uri-dstar", auth.ACL{}, "spiffe://example.org/**"),
		mk("uri-slash", auth.ACL{}, "https://other.org/p/q"),
		mk("uri-any", auth.ACL{}, "**"),
		mk("uri-none", auth.ACL{}, "spiffe://example.org/ns/prod/sa/*/x", "https://other.org/p"),
		mk("combo", auth.ACL{AllowedCNs: []string{"other.example"}, AllowedOUs: []string{"ops"}, AllowedDNSs: []string{"b.example"}, AllowedIPs: []net.IP{net.ParseIP("::1")}}, "spiffe://example.org/ns/dev/**"),
		mk("combo-order", auth.ACL{AllowedCNs: []string{"client.example"}, AllowedOUs: []string{"ops", "dev"}, AllowedDNSs: []string{"a.example"}, AllowedIPs: []net.IP{net.ParseIP("10.0.0.7")}}, "**"),
		mk("policy", auth.ACL{AllowOPAQuery: pol}),
		mk("policy-ou", auth.ACL{AllowedOUs: []string{"qa"}, AllowOPAQuery: pol}),
		mk("policy-cn-ou", auth.ACL{AllowedCNs: []string{"client.example"}, AllowedOUs: []string{"ops"}, AllowOPAQuery: pol}),
		mk("policy-ip", auth.ACL{AllowedIPs: []net.IP{net.ParseIP("192.0.2.9")}, AllowOPAQuery: pol}),
	}
}

// diffCycle is a cycle over the test PKI with a judge holding the query,
// on the trace root whose material store holds the CA bundle.
func (p *diffPKI) diffCycle() *substanceCycle {
	cache := &substanceCache{}
	cache.reset(1)
	return &substanceCycle{judge: substanceJudge{PolicyQuery: diffQuery}, root: p.store, cache: cache, chains: map[string]*substanceChain{}, cas: map[string]*substanceCA{}, files: map[string]*substanceFile{}}
}

func diffChain(ents ...*subEntity) *substanceChain {
	der := subChainDER(ents...)
	certs := make([]*x509.Certificate, len(ents))
	for i, e := range ents {
		certs[i] = e.cert
	}
	return &substanceChain{hash: substanceHash(der), certs: certs}
}

func diffRaw(ents ...*subEntity) [][]byte {
	out := make([][]byte, len(ents))
	for i, e := range ents {
		out[i] = e.der
	}
	return out
}

// TestSubstanceDifferentialRules: on every leaf and every rule set, the
// mirror's decision equals the proxy verifier's, and on allow the
// mirror's rule equals ServerRule's.
func TestSubstanceDifferentialRules(t *testing.T) {
	p := diffMint(t)
	leaves := p.diffLeaves(t)
	sets := p.diffRuleSets(t)
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cy := p.diffCycle()
	cases, allows := 0, 0
	for _, set := range sets {
		rules := substanceParseRules(set.recorded)
		if len(rules.unknown) > 0 {
			t.Fatalf("%s: the mirror cannot read %v", set.name, set.recorded)
		}
		for i, leaf := range leaves {
			cases++
			raw := diffRaw(leaf, p.inter)
			verified := [][]*x509.Certificate{{leaf.cert, p.inter.cert, p.root.cert}}
			err := set.acl.VerifyPeerCertificateServer(raw, verified)
			wantDecision := "deny"
			if err == nil {
				wantDecision = "allow"
				allows++
			}
			decision, rule, derr := cy.decide(rules, diffChain(leaf, p.inter), p.mat, at)
			if derr != nil {
				t.Fatalf("%s leaf %d: the mirror could not decide: %v", set.name, i, derr)
			}
			if decision != wantDecision {
				t.Errorf("%s leaf %d (%s): mirror %s, proxy %s (%v)", set.name, i, diffDescribe(leaf), decision, wantDecision, err)
				continue
			}
			if decision == "allow" {
				if want := set.acl.ServerRule(raw, verified); rule != want {
					t.Errorf("%s leaf %d (%s): mirror rule %s, proxy %s", set.name, i, diffDescribe(leaf), rule, want)
				}
			}
		}
	}
	if allows == 0 || allows == cases {
		t.Fatalf("the matrix is one-sided: %d allows of %d", allows, cases)
	}
	t.Logf("rules: %d leaves x %d rule sets = %d cases, %d allowed by both", len(leaves), len(sets), cases, allows)
}

func diffDescribe(e *subEntity) string {
	c := e.cert
	var uris []string
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	return fmt.Sprintf("cn=%q ou=%v dns=%v ip=%v uri=%v", c.Subject.CommonName, c.Subject.OrganizationalUnit, c.DNSNames, c.IPAddresses, uris)
}

// TestSubstanceDifferentialVerification: on a matrix of chains and
// times, the mirror verifies exactly when the proxy's chain verifier does
// (auth.ACL.VerifyPeerCertificateServerFor: roots the bundle, the
// intermediates presented, client authentication, the time given).
func TestSubstanceDifferentialVerification(t *testing.T) {
	p := diffMint(t)
	from, until := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := func(tmpl x509.Certificate, issuer *subEntity) *subEntity {
		if tmpl.NotBefore.IsZero() {
			tmpl.NotBefore, tmpl.NotAfter = from, until
		}
		if tmpl.Subject.CommonName == "" {
			tmpl.Subject.CommonName = "client.example"
		}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		return subIssue(t, &tmpl, issuer)
	}
	client := x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	rogue := subIssue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Rogue"}, NotBefore: from, NotAfter: until, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	oldInter := subIssue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Old Intermediate"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, p.root)
	valid := leaf(client, p.inter)
	chains := map[string][]*subEntity{
		"valid":                {valid, p.inter},
		"missing-intermediate": {valid},
		"with-root":            {valid, p.inter, p.root},
		"root-first":           {p.root, p.inter, valid},
		"expired":              {leaf(x509.Certificate{NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), ExtKeyUsage: client.ExtKeyUsage}, p.inter), p.inter},
		"not-yet":              {leaf(x509.Certificate{NotBefore: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: until, ExtKeyUsage: client.ExtKeyUsage}, p.inter), p.inter},
		"rogue":                {leaf(client, rogue), rogue},
		"server-auth-only":     {leaf(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, p.inter), p.inter},
		"any-eku":              {leaf(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}, p.inter), p.inter},
		"no-eku":               {leaf(x509.Certificate{}, p.inter), p.inter},
		"old-intermediate":     {leaf(client, oldInter), oldInter},
		"direct":               {leaf(client, p.root)},
		"self-signed":          {leaf(client, nil)},
	}
	times := []time.Time{time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2031, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)}
	pool := subPool(p.root)
	cy := p.diffCycle()
	ca := cy.ca(p.mat["ca"])
	if ca.pool == nil {
		t.Fatal("the CA bundle did not load")
	}
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)
	cases, agreedTrue := 0, 0
	for _, name := range names {
		ents := chains[name]
		for _, at := range times {
			cases++
			now := at
			verify := auth.ACL{AllowAll: true}.VerifyPeerCertificateServerFor(pool, func() time.Time { return now })
			want := verify(diffRaw(ents...), nil) == nil
			// A fresh memory per case, then the memory's answer.
			fresh := p.diffCycle()
			fresh.cas = cy.cas
			got := fresh.verified(diffChain(ents...), ca, at)
			if got != want {
				t.Errorf("%s at %s: mirror %v, proxy %v", name, at.Format(time.RFC3339), got, want)
			}
			if got && want {
				agreedTrue++
			}
			if again := fresh.verified(diffChain(ents...), ca, at); again != got {
				t.Errorf("%s at %s: the memory answers %v after %v", name, at.Format(time.RFC3339), again, got)
			}
		}
	}
	if agreedTrue == 0 {
		t.Fatal("nothing verified")
	}
	t.Logf("verification: %d chains x %d times = %d cases, %d verified by both", len(chains), len(times), cases, agreedTrue)
}

// TestSubstanceDifferentialPins: in pin mode the mirror's decision equals
// the proxy's pin check, over the leaf matrix's keys and the three
// algorithms, from the recorded form of each pin.
func TestSubstanceDifferentialPins(t *testing.T) {
	p := diffMint(t)
	leaves := p.diffLeaves(t)[:27]
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cy := p.diffCycle()
	digest := func(algo string, spki []byte) string {
		var sum []byte
		switch algo {
		case "sha256":
			s := sha256.Sum256(spki)
			sum = s[:]
		case "sha384":
			s := sha512.Sum384(spki)
			sum = s[:]
		case "sha512":
			s := sha512.Sum512(spki)
			sum = s[:]
		}
		return algo + ":" + base64.StdEncoding.EncodeToString(sum)
	}
	cases, allows := 0, 0
	for _, algo := range []string{"sha256", "sha384", "sha512"} {
		for i := 0; i < len(leaves); i += 9 {
			pinned := []string{digest(algo, leaves[i].cert.RawSubjectPublicKeyInfo), digest("sha256", leaves[(i+3)%len(leaves)].cert.RawSubjectPublicKeyInfo)}
			pins, err := auth.ParseSPKIPins(pinned)
			if err != nil {
				t.Fatal(err)
			}
			acl := auth.ACL{AllowedPins: pins}
			rules := substanceParseRules(diffRecord(acl, nil, ""))
			if len(rules.unknown) > 0 || len(rules.pins) != 2 {
				t.Fatalf("the mirror cannot read the recorded pins %v", diffRecord(acl, nil, ""))
			}
			for k, leaf := range leaves {
				cases++
				want := "deny"
				if acl.VerifyPeerCertificateServer(diffRaw(leaf, p.inter), nil) == nil {
					want = "allow"
					allows++
				}
				got, rule, derr := cy.decide(rules, diffChain(leaf, p.inter), p.mat, at)
				if derr != nil || got != want || (got == "allow" && rule != acl.ServerRule(diffRaw(leaf, p.inter), nil)) {
					t.Errorf("%s pin of leaf %d on leaf %d: mirror %s/%s (%v), proxy %s", algo, i, k, got, rule, derr, want)
				}
			}
		}
	}
	if allows == 0 || allows == cases {
		t.Fatalf("the matrix is one-sided: %d allows of %d", allows, cases)
	}
	t.Logf("pins: %d cases, %d allowed by both", cases, allows)
}

// TestSubstanceDifferentialPolicyLoad: the policy compiled from the
// hashed bytes evaluates as the proxy's own loader's (policy.LoadFromPath,
// which reads the path) on every leaf.
func TestSubstanceDifferentialPolicyLoad(t *testing.T) {
	p := diffMint(t)
	leaves := p.diffLeaves(t)
	pol, err := policy.LoadFromPath(p.policyPath, diffQuery)
	if err != nil {
		t.Fatal(err)
	}
	acl := auth.ACL{AllowOPAQuery: pol, OPAQueryTimeout: 10 * time.Second}
	cy := p.diffCycle()
	pq, err := cy.policy(p.mat["policy"], p.policyHash)
	if err != nil {
		t.Fatal(err)
	}
	allows := 0
	for i, leaf := range leaves {
		want := acl.VerifyPeerCertificateServer(diffRaw(leaf, p.inter), [][]*x509.Certificate{{leaf.cert}}) == nil
		got, cacheable, err := substanceEvalPolicy(pq, leaf.cert)
		if err != nil || got != want || !cacheable {
			t.Errorf("leaf %d (%s): mirror %v (cacheable %v, %v), proxy %v", i, diffDescribe(leaf), got, cacheable, err, want)
		}
		if got {
			allows++
		}
	}
	if allows == 0 || allows == len(leaves) {
		t.Fatalf("the policy is one-sided: %d allows of %d", allows, len(leaves))
	}
	t.Logf("policy: %d leaves, %d allowed by both", len(leaves), allows)
	// A policy that consults the clock is evaluated the same and not
	// remembered by either.
	clock := "package policy\n\ndefault allow = false\n\nallow {\n\ttime.now_ns() > 0\n\tinput.certificate.Subject.CommonName == \"client.example\"\n}\n"
	clockPath := filepath.Join(t.TempDir(), "clock.rego")
	if err := os.WriteFile(clockPath, []byte(clock), 0o644); err != nil {
		t.Fatal(err)
	}
	hash := substanceHash([]byte(clock))
	pq, err = cy.policy(&gtMaterial{Material: "policy", Path: clockPath, SHA256: &hash}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if got, cacheable, err := substanceEvalPolicy(pq, leaves[0].cert); err != nil || !got || cacheable {
		t.Fatalf("clock policy: %v, cacheable %v, %v", got, cacheable, err)
	}
	if !strings.HasPrefix(leaves[0].cert.Subject.CommonName, "client") {
		t.Fatal("the first leaf is not the client")
	}
}

// diffBundle is a bundle tarball, as opa build writes one: a gzipped tar
// of the files given.
func diffBundle(t testing.TB, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// diffPolicyForms are a policy file in each form the proxy loads, the
// .rego module and the bundle, each with a second content that decides
// otherwise on the leaf matrix.
func diffPolicyForms(t testing.TB) []struct {
	name        string
	first, next []byte
} {
	t.Helper()
	const bundlePolicy = "package policy\n\ndefault allow := false\n\nallow if input.certificate.Subject.CommonName == \"client.example\"\n\nallow if \"dev\" in input.certificate.Subject.OrganizationalUnit\n"
	const bundleOther = "package policy\n\ndefault allow := false\n\nallow if input.certificate.Subject.CommonName == \"other.example\"\n"
	const regoOther = "package policy\n\ndefault allow = false\n\nallow {\n\tinput.certificate.Subject.CommonName == \"other.example\"\n}\n"
	return []struct {
		name        string
		first, next []byte
	}{
		{"policy.rego", []byte(diffPolicy), []byte(regoOther)},
		{"bundle.tar.gz", diffBundle(t, map[string]string{"policy.rego": bundlePolicy}), diffBundle(t, map[string]string{"policy.rego": bundleOther})},
	}
}

// diffProxyAllows is the proxy's decision on each leaf under the policy
// the proxy prepares from data at path (policy.Prepare), through its own
// verifier.
func diffProxyAllows(t testing.TB, p *diffPKI, leaves []*subEntity, path string, data []byte) []bool {
	t.Helper()
	pq, err := policy.Prepare(path, diffQuery, data)
	if err != nil {
		t.Fatalf("the proxy's loader refused %s: %v", path, err)
	}
	acl := auth.ACL{AllowOPAQuery: policy.WrapForTest(&pq), OPAQueryTimeout: 10 * time.Second}
	out := make([]bool, len(leaves))
	for i, leaf := range leaves {
		out[i] = acl.VerifyPeerCertificateServer(diffRaw(leaf, p.inter), [][]*x509.Certificate{{leaf.cert}}) == nil
	}
	return out
}

// diffMirrorAllows is the mirror's decision on each leaf under the query
// it compiled.
func diffMirrorAllows(t testing.TB, pq *rego.PreparedEvalQuery, leaves []*subEntity) []bool {
	t.Helper()
	out := make([]bool, len(leaves))
	for i, leaf := range leaves {
		allowed, _, err := substanceEvalPolicy(pq, leaf.cert)
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		out[i] = allowed
	}
	return out
}

// TestSubstanceDifferentialPolicyForms: a .rego file and a bundle, each
// compiled by the mirror from the bytes it hashed, decide on every leaf as
// the proxy's policy.Prepare does on the same bytes.
func TestSubstanceDifferentialPolicyForms(t *testing.T) {
	p := diffMint(t)
	leaves := p.diffLeaves(t)
	for _, form := range diffPolicyForms(t) {
		path := filepath.Join(t.TempDir(), form.name)
		if err := os.WriteFile(path, form.first, 0o644); err != nil {
			t.Fatal(err)
		}
		hash := substanceHash(form.first)
		pq, err := p.diffCycle().policy(&gtMaterial{Material: "policy", Path: path, SHA256: &hash}, hash)
		if err != nil {
			t.Fatalf("%s: the mirror did not compile it: %v", form.name, err)
		}
		got, want := diffMirrorAllows(t, pq, leaves), diffProxyAllows(t, p, leaves, path, form.first)
		allows := 0
		for i := range leaves {
			if got[i] != want[i] {
				t.Errorf("%s leaf %d (%s): mirror %v, proxy %v", form.name, i, diffDescribe(leaves[i]), got[i], want[i])
			}
			if want[i] {
				allows++
			}
		}
		if allows == 0 || allows == len(leaves) {
			t.Fatalf("%s is one-sided: %d allows of %d", form.name, allows, len(leaves))
		}
		t.Logf("%s: %d leaves, %d allowed by both", form.name, len(leaves), allows)
	}
}

// TestSubstancePolicyCompiledFromTheHashedBytes: the file rewritten
// between the hash and the compile changes nothing of what is compiled,
// in either form: the query decides as the proxy does on the bytes hashed,
// and not as on the bytes that replaced them. The next cycle reads the
// replacement, which no longer hashes to the recorded hash, and fails.
func TestSubstancePolicyCompiledFromTheHashedBytes(t *testing.T) {
	p := diffMint(t)
	leaves := p.diffLeaves(t)
	for _, form := range diffPolicyForms(t) {
		path := filepath.Join(t.TempDir(), form.name)
		if err := os.WriteFile(path, form.first, 0o644); err != nil {
			t.Fatal(err)
		}
		prev := substancePolicyHashed
		rewrote := 0
		substancePolicyHashed = func(p string) {
			if p == path {
				rewrote++
				if err := os.WriteFile(path, form.next, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		hash := substanceHash(form.first)
		m := &gtMaterial{Material: "policy", Path: path, SHA256: &hash}
		pq, err := p.diffCycle().policy(m, hash)
		substancePolicyHashed = prev
		if err != nil || rewrote != 1 {
			t.Fatalf("%s: compiled %v after %d rewrites", form.name, err, rewrote)
		}
		got := diffMirrorAllows(t, pq, leaves)
		if want := diffProxyAllows(t, p, leaves, path, form.first); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the mirror decided otherwise than the proxy on the bytes hashed", form.name)
		}
		if replaced := diffProxyAllows(t, p, leaves, path, form.next); reflect.DeepEqual(got, replaced) {
			t.Fatalf("%s: the two contents decide alike, so the rewrite proves nothing", form.name)
		}
		if _, err := p.diffCycle().policy(m, hash); err == nil {
			t.Fatalf("%s: the rewritten file was compiled under the recorded hash", form.name)
		}
	}
}
