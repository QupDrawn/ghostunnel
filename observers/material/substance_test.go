package main

// substance_test.go proves the two substance rules (substance.go) on
// synthetic boots written in the exact ringtrace format over the committed
// test PKI (observers/testdata/pki, gtreader_test.go): one boot per
// fail-closed branch that yields exactly the expected finding, the
// agreeing boots that yield nothing, and the memory's keys and reset.
// Every member carries a byte-identical copy of this file. The mirror's
// agreement with the proxy's own code is substance_diff_test.go.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The material entries of the committed test PKI as a start line names
// them, relative to the package directory go test runs in.
const (
	subCA     = `{"material":"ca","path":"../testdata/pki/ca.pem","sha256":"` + gtCAHash + `"}`
	subPolicy = `{"material":"policy","path":"../testdata/pki/policy.rego","sha256":"` + gtPolicyHash + `"}`
	subAt     = "2026-09-24T11:00:01Z"
)

// subConfig is a server start-line config with the given rule set and
// material entries (JSON objects).
func subConfig(acl []string, material ...string) string {
	return subConfigMode("server", acl, material...)
}

func subConfigMode(mode string, acl []string, material ...string) string {
	quoted := make([]string, len(acl))
	for i, r := range acl {
		quoted[i] = fmt.Sprintf("%q", r)
	}
	return fmt.Sprintf(`{"mode":%q,"listen":"localhost:8443","target":"localhost:8080","proxy_protocol":"off","status_listen":"127.0.0.1:6060","status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":[%s],"lifetime_cap_seconds":300,"sandbox_state":"applied","sandbox_accepted":null,"material":[%s],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`, mode, strings.Join(quoted, ","), strings.Join(material, ","))
}

func subHdr(kind string, at string) string {
	return fmt.Sprintf(`{"kind":"%s","version":1,"sequence":0,"at":"%s"`, kind, at)
}

func subStart(at string, boot int, config string) string {
	return fmt.Sprintf(`%s,"boot":%d,"pid":4242,"config":%s}`, subHdr("start", at), boot, config)
}

func subAccept(at string, conn int) string {
	return fmt.Sprintf(`%s,"conn":%d,"listener":"127.0.0.1:8443","remote":"10.0.0.7:5%04d"}`, subHdr("accept", at), conn, conn)
}

// subHandshake is a handshake line naming chain, or none when chain is "".
func subHandshake(at string, conn int, outcome string, resumed, verified bool, chain string) string {
	line := fmt.Sprintf(`%s,"conn":%d,"outcome":"%s","resumed":%t,"verified":%t,"protocol":"TLS1.3","peer":null,"error":null`, subHdr("handshake", at), conn, outcome, resumed, verified)
	if chain != "" {
		line += `,"chain":"` + chain + `"`
	}
	return line + "}"
}

func subACL(at string, conn int, decision, rule string) string {
	return fmt.Sprintf(`%s,"conn":%d,"decision":"%s","rule":"%s","reason":"r"}`, subHdr("acl", at), conn, decision, rule)
}

func subClose(at string, conn int, reason string) string {
	return fmt.Sprintf(`%s,"conn":%d,"reason":"%s","duration_ms":3}`, subHdr("close", at), conn, reason)
}

func subReload(at string, outcome string, material ...string) string {
	return fmt.Sprintf(`%s,"outcome":"%s","error":null,"serving":true,"material":[%s]}`, subHdr("reload", at), outcome, strings.Join(material, ","))
}

// subServed is a connection that presented chain, was verified and was
// allowed under rule, then closed.
func subServed(at string, conn int, chain, rule string) []string {
	return []string{subAccept(at, conn), subHandshake(at, conn, "ok", false, true, chain), subACL(at, conn, "allow", rule), subClose(at, conn, "eof")}
}

// subDenied is a connection that presented chain, whose handshake was
// verified, and that was denied under none and closed as refused.
func subDenied(at string, conn int, chain string) []string {
	return []string{subAccept(at, conn), subHandshake(at, conn, "ok", false, true, chain), subACL(at, conn, "deny", "none"), subClose(at, conn, "refused")}
}

// subRefused is a connection whose handshake was refused over its chain
// (verified false, acl deny under none), as the proxy records one.
func subRefused(at string, conn int, chain string) []string {
	return []string{subAccept(at, conn), subHandshake(at, conn, "refused", false, false, chain), subACL(at, conn, "deny", "none"), subClose(at, conn, "refused")}
}

// subTree writes one boot of the lines, renumbered, under a fresh root
// that carries the test PKI's chains, and returns the root.
func subTree(t *testing.T, lines ...string) string {
	t.Helper()
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	return root
}

// tRenumberLines rewrites each line's sequence to its position.
func tRenumberLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		s := strings.Index(line, `"sequence":`) + len(`"sequence":`)
		e := s + strings.Index(line[s:], ",")
		out[i] = line[:s] + fmt.Sprint(i+1) + line[e:]
	}
	return out
}

// subJudge is the judge the tests run with: the committed policy's query
// and no memory across runs unless a test keeps one.
func subJudge() substanceJudge {
	return substanceJudge{PolicyQuery: gtPolicyQueryPKI}
}

// subRun reads the root's current boot and judges it by the substance
// rules, returning the findings sorted.
func subRun(t *testing.T, root string, j substanceJudge) []Finding {
	t.Helper()
	boot, err := gtReadLatest(root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := substanceFindings(boot, j)
	sort.Slice(got, func(i, k int) bool {
		if got[i].Check != got[k].Check {
			return got[i].Check < got[k].Check
		}
		return got[i].Subject < got[k].Subject
	})
	return got
}

func subWant(t *testing.T, got []Finding, want ...Finding) {
	t.Helper()
	sort.Slice(want, func(i, k int) bool {
		if want[i].Check != want[k].Check {
			return want[i].Check < want[k].Check
		}
		return want[i].Subject < want[k].Subject
	})
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings\n got %v\nwant %v", got, want)
	}
}

func hsFail(conn int) Finding  { return Finding{checkHandshakeSubstance, fmt.Sprint(conn)} }
func aclFail(conn int) Finding { return Finding{checkACLSubstance, fmt.Sprint(conn)} }

// subLines is a start line under the rule set with the CA (and the policy
// when the set names one) followed by the connections given.
func subLines(acl []string, conns ...[]string) []string {
	material := []string{subCA}
	for _, r := range acl {
		if strings.HasPrefix(r, "policy:") {
			material = append(material, subPolicy)
		}
	}
	lines := []string{subStart(subAt, 1, subConfig(acl, material...))}
	for _, c := range conns {
		lines = append(lines, c...)
	}
	return lines
}

// ---- agreement ----

func TestSubstanceAgreesWithAnHonestTrace(t *testing.T) {
	acl := []string{"allow-cn:client.example"}
	lines := subLines(acl,
		subServed(subAt, 1, gtChainClient, "allow-cn"),
		subDenied(subAt, 2, gtChainOther),
		// Resumed, re-verified, the same chain.
		[]string{subAccept(subAt, 3), subHandshake(subAt, 3, "ok", true, true, gtChainClient), subACL(subAt, 3, "allow", "allow-cn"), subClose(subAt, 3, "eof")},
		// Refused over a chain the CA does not sign: the member agrees
		// with the denial, and has nothing to re-verify.
		subRefused(subAt, 4, gtChainRogue),
		// Refused with no certificate presented.
		[]string{subAccept(subAt, 5), subHandshake(subAt, 5, "refused", false, false, ""), subACL(subAt, 5, "deny", "none"), subClose(subAt, 5, "refused")},
		// A handshake that failed before any certificate was judged: no
		// acl line, nothing to re-judge.
		[]string{subAccept(subAt, 6), subHandshake(subAt, 6, "refused", false, false, ""), subClose(subAt, 6, "error")},
		// The acl line before the handshake line: paired by conn.
		[]string{subAccept(subAt, 7), subACL(subAt, 7, "allow", "allow-cn"), subHandshake(subAt, 7, "ok", false, true, gtChainClient), subClose(subAt, 7, "eof")},
	)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))

	// With a policy beside the rule: the other chain is denied by the
	// policy too (CN other.example, OU guests).
	acl = []string{"allow-cn:client.example", "policy:" + gtPolicyHash}
	lines = subLines(acl, subServed(subAt, 1, gtChainClient, "allow-cn"), subDenied(subAt, 2, gtChainOther))
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))

	// Every rule kind, on the leaves that carry the value.
	for _, c := range []struct {
		rule  string
		chain string
	}{
		{"allow-ou:ops", gtChainClient},
		{"allow-dns:client.internal", gtChainClient},
		{"allow-ip:10.0.0.7", gtChainClient},
		{"allow-uri:spiffe://example.org/ns/prod/sa/client", gtChainClient},
		{"allow-uri:spiffe://example.org/ns/*/sa/*", gtChainClient},
		{"allow-uri:spiffe://example.org/**", gtChainOther},
		{"allow-all", gtChainOther},
	} {
		name := strings.SplitN(c.rule, ":", 2)[0]
		lines = subLines([]string{c.rule}, subServed(subAt, 1, c.chain, name))
		subWant(t, subRun(t, subTree(t, lines...), subJudge()))
	}
}

func TestSubstanceEmptyBootHasNothingToJudge(t *testing.T) {
	root := subTree(t, subStart(subAt, 1, subConfig([]string{"allow-cn:client.example"}, subCA)))
	subWant(t, subRun(t, root, subJudge()))
}

// ---- the handshake line ----

func TestSubstanceVerifiedHandshakeMustNameAChain(t *testing.T) {
	lines := subLines([]string{"allow-cn:client.example"},
		[]string{subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, true, ""), subACL(subAt, 1, "allow", "allow-cn"), subClose(subAt, 1, "eof")},
	)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(1), aclFail(1))
	// An unverified handshake without a chain is not the handshake
	// rule's; its allow is still one the member cannot confirm.
	lines = subLines([]string{"allow-cn:client.example"},
		[]string{subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, false, ""), subACL(subAt, 1, "allow", "allow-cn"), subClose(subAt, 1, "eof")},
	)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1))
}

func TestSubstanceACLWithoutAHandshake(t *testing.T) {
	lines := subLines([]string{"allow-cn:client.example"},
		[]string{subAccept(subAt, 1), subACL(subAt, 1, "allow", "allow-cn"), subClose(subAt, 1, "eof")},
		[]string{subAccept(subAt, 2), subACL(subAt, 2, "deny", "none"), subClose(subAt, 2, "refused")},
	)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1), aclFail(2))
}

// ---- the chain store ----

// subChainFailure is what a chain that cannot be read yields on a served
// connection: both rules fail on it.
func subChainFailure(t *testing.T, root string) {
	t.Helper()
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
}

func TestSubstanceChainMissing(t *testing.T) {
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	if err := os.Remove(filepath.Join(root, "chains", gtChainClient+".der")); err != nil {
		t.Fatal(err)
	}
	subChainFailure(t, root)
	// The whole store gone.
	if err := os.RemoveAll(filepath.Join(root, "chains")); err != nil {
		t.Fatal(err)
	}
	subChainFailure(t, root)
}

func TestSubstanceChainTmpOnlyIsAbsent(t *testing.T) {
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	dir := filepath.Join(root, "chains")
	// The right bytes under <hash>.tmp only: a write that never renamed.
	if err := os.Rename(filepath.Join(dir, gtChainClient+".der"), filepath.Join(dir, gtChainClient+".tmp")); err != nil {
		t.Fatal(err)
	}
	subChainFailure(t, root)
}

func TestSubstanceChainMishashed(t *testing.T) {
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	dir := filepath.Join(root, "chains")
	// The other chain's bytes, which verify and parse, under the client
	// chain's name: refused by the hash, before anything is parsed.
	other, err := os.ReadFile(filepath.Join(dir, gtChainOther+".der"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, gtChainClient+".der"), other, 0o644); err != nil {
		t.Fatal(err)
	}
	subChainFailure(t, root)
	// One byte changed in the right bytes.
	client, err := os.ReadFile(filepath.Join(gtPKI, "chains", gtChainClient+".der"))
	if err != nil {
		t.Fatal(err)
	}
	client[len(client)-1] ^= 0x01
	if err := os.WriteFile(filepath.Join(dir, gtChainClient+".der"), client, 0o644); err != nil {
		t.Fatal(err)
	}
	subChainFailure(t, root)
}

// subNamedChain writes content under chains/<sha256(content)>.der and
// returns the name, so that a test isolates one reader rule from the
// hash rule.
func subNamedChain(t *testing.T, root string, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	name := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(root, "chains", name+".der"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestSubstanceChainNotDER(t *testing.T) {
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	// A PEM certificate, correctly named: not a DER concatenation.
	pemBytes, err := os.ReadFile(filepath.Join(gtPKI, "leaf-client.pem"))
	if err != nil {
		t.Fatal(err)
	}
	name := subNamedChain(t, root, pemBytes)
	lines := subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, name, "allow-cn"))
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	subChainFailure(t, root)
	// Garbage, correctly named.
	name = subNamedChain(t, root, []byte("not a certificate"))
	lines = subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, name, "allow-cn"))
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	subChainFailure(t, root)
}

func TestSubstanceChainOversize(t *testing.T) {
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	// The client chain padded past the bound with zero bytes, under the
	// name of the padded content: refused by size, before any read.
	client, err := os.ReadFile(filepath.Join(gtPKI, "chains", gtChainClient+".der"))
	if err != nil {
		t.Fatal(err)
	}
	big := append(client, make([]byte, substanceMaxChainBytes+1-len(client))...)
	name := subNamedChain(t, root, big)
	lines := subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, name, "allow-cn"))
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	subChainFailure(t, root)
}

func TestSubstanceChainNotARegularFile(t *testing.T) {
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	dir := filepath.Join(root, "chains")
	p := filepath.Join(dir, gtChainClient+".der")
	// A directory at the name.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	subChainFailure(t, root)
	// A symbolic link to the right bytes: judged as the link, refused.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "elsewhere.der")
	client, err := os.ReadFile(filepath.Join(gtPKI, "chains", gtChainClient+".der"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, client, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		// Windows without the privilege: the directory case above stands
		// for the rule; the link case is confirmed on hosts that can
		// make one.
		t.Logf("symlink not made, the link case is not run here: %v", err)
		return
	}
	subChainFailure(t, root)
}

func TestSubstanceChainNameShape(t *testing.T) {
	// The decoder refuses a chain key that is not a hash, so the reader
	// sees only well-formed names from a boot; the reader's own rule
	// holds anyway, so a name is never a path.
	cy := &substanceCycle{judge: subJudge(), root: t.TempDir(), cache: &substanceCache{}, chains: map[string]*substanceChain{}, cas: map[string]*substanceCA{}, files: map[string]*substanceFile{}}
	cy.cache.reset(1)
	for _, bad := range []string{"", "..", "../" + gtChainClient, strings.ToUpper(gtChainClient), gtChainClient[:63], gtChainClient + "0"} {
		if c := cy.chain(bad); c.certs != nil {
			t.Errorf("%q read a chain", bad)
		}
	}
}

// ---- the CA material ----

// TestSubstanceCAAbsentFromTheStoreOrMishashed: the CA bundle is read from
// the material store under the trace root by the recorded hash, never
// from the path the entry names. Nothing to judge by, so both rules fail:
// no ca entry; the system trust store; a recorded hash the store lacks,
// whether the file at the path is the committed CA or a .tmp is all the
// store holds; the store holding under the hash bytes that do not hash
// to it; bytes that hash as recorded but hold no certificate. Judged and
// refused: the rogue CA, stored and recorded as it is, which did not
// sign the chain. And judged with nothing found: the bundle in the store
// under its hash with no file at the path at all.
func TestSubstanceCAAbsentFromTheStoreOrMishashed(t *testing.T) {
	served := subServed(subAt, 1, gtChainClient, "allow-cn")
	acl := []string{"allow-cn:client.example"}
	boot := func(material ...string) string {
		return subTree(t, append([]string{subStart(subAt, 1, subConfig(acl, material...))}, served...)...)
	}
	// Absent from the start line.
	subWant(t, subRun(t, boot(), subJudge()), hsFail(1), aclFail(1))
	// The system trust store (empty path, no hash): not judgeable.
	subWant(t, subRun(t, boot(`{"material":"ca","path":"","sha256":null}`), subJudge()), hsFail(1), aclFail(1))
	// A hash the store lacks, the file at the path being the committed CA
	// whose bytes the store holds under another name: the path is not
	// read.
	subWant(t, subRun(t, boot(`{"material":"ca","path":"../testdata/pki/ca.pem","sha256":"`+gtPolicyHash+`"}`), subJudge()), hsFail(1), aclFail(1))
	// A hash the store holds only as <hash>.tmp, a write that never
	// renamed: absent.
	pending := []byte("a bundle whose write never completed\n")
	root := boot(fmt.Sprintf(`{"material":"ca","path":"/etc/gt/ca.pem","sha256":"%s"}`, substanceHash(pending)))
	if err := os.WriteFile(filepath.Join(root, "material", substanceHash(pending)+".tmp"), pending, 0o644); err != nil {
		t.Fatal(err)
	}
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
	// The store holding, under the committed CA's hash, bytes that do not
	// hash to it (the rogue bundle under the committed CA's name).
	rogue, err := os.ReadFile(filepath.Join(gtPKI, "rogue-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	root = boot(subCA)
	if err := os.WriteFile(filepath.Join(root, "material", gtCAHash), rogue, 0o644); err != nil {
		t.Fatal(err)
	}
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
	// Bytes that hash as recorded but hold no certificate.
	nothing := []byte("nothing\n")
	root = boot(fmt.Sprintf(`{"material":"ca","path":"/etc/gt/ca.pem","sha256":"%s"}`, substanceHash(nothing)))
	subStoreMaterial(t, root, nothing)
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
	// The wrong CA, stored and recorded as it is: the chain does not
	// verify.
	subWant(t, subRun(t, boot(fmt.Sprintf(`{"material":"ca","path":"../testdata/pki/rogue-ca.pem","sha256":"%s"}`, substanceHash(rogue))), subJudge()), hsFail(1), aclFail(1))
	// The bundle in the store under its hash and no file at the path:
	// judged from the store, and the account holds.
	subWant(t, subRun(t, boot(`{"material":"ca","path":"../testdata/pki/absent.pem","sha256":"`+gtCAHash+`"}`), subJudge()))
}

// TestSubstanceMaterialBaseResolvesRelativePaths: a relative policy path
// resolves against the base when one is set (the fixture harness), as
// given otherwise (the package directory here). The CA bundle has no path
// to resolve: it is read from the material store by hash, so the
// handshake rule holds either way and only the policy's rule turns.
func TestSubstanceMaterialBaseResolvesRelativePaths(t *testing.T) {
	lines := subLines([]string{"policy:" + gtPolicyHash}, subServed(subAt, 1, gtChainClient, "policy"))
	root := subTree(t, lines...)
	j := subJudge()
	j.MaterialBase = t.TempDir()
	subWant(t, subRun(t, root, j), aclFail(1))
	base := filepath.Join(t.TempDir(), "x")
	if err := os.MkdirAll(filepath.Join(base, "..", "testdata", "pki"), 0o755); err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(gtPKI, "policy.rego"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "..", "testdata", "pki", "policy.rego"), policy, 0o644); err != nil {
		t.Fatal(err)
	}
	j.MaterialBase = base
	subWant(t, subRun(t, root, j))
}

// ---- the chain against the CA ----

func TestSubstanceChainDoesNotVerify(t *testing.T) {
	acl := []string{"allow-cn:client.example"}
	// Signed by a CA the bundle does not hold; the proxy says verified
	// and allowed (the leaf's CN would match).
	root := subTree(t, subLines(acl, subServed(subAt, 1, gtChainRogue, "allow-cn"))...)
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
	// The client leaf without its intermediate: the chain does not build.
	leafOnly, err := os.ReadFile(filepath.Join(gtPKI, "leaf-client.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leafOnly)
	root = subTree(t, subLines(acl, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	name := subNamedChain(t, root, block.Bytes)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(subLines(acl, subServed(subAt, 1, name, "allow-cn")))...))
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
	// Expired at the handshake's time (valid in 2020 only).
	root = subTree(t, subLines(acl, subServed(subAt, 1, gtChainExpired, "allow-cn"))...)
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
	// The proxy denied it under none: the member agrees, the handshake
	// rule has nothing to say about an unverified handshake.
	root = subTree(t, subLines(acl, subRefused(subAt, 1, gtChainExpired))...)
	subWant(t, subRun(t, root, subJudge()))
}

func TestSubstanceTheRecordedTimeGoverns(t *testing.T) {
	// A PKI of this test: a CA valid 2019 to 2030 and a leaf valid in
	// 2020 only, so that the chain verifies at a 2020 handshake and not
	// at the member's now (2026 in the committed PKI's boots, later on
	// any host running this).
	from2019, to2030 := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ca := subIssue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Time CA"}, NotBefore: from2019, NotAfter: to2030, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	leaf := subIssue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "client.example"}, NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca)
	root := t.TempDir()
	caMaterial := subStoreCA(t, root, ca)
	acl := []string{"allow-cn:client.example"}
	then := "2020-06-01T00:00:00Z"
	chain := subWriteChain(t, root, leaf.der)
	lines := []string{subStart(then, 1, subConfig(acl, caMaterial))}
	lines = append(lines, subServed(then, 1, chain, "allow-cn")...)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	subWant(t, subRun(t, root, subJudge()))
	if _, err := leaf.cert.Verify(x509.VerifyOptions{Roots: subPool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("the leaf verifies now; the test needs one that does not")
	}
	// The same lines dated 2026: the leaf has expired.
	lines = []string{subStart(subAt, 1, subConfig(acl, caMaterial))}
	lines = append(lines, subServed(subAt, 1, chain, "allow-cn")...)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	subWant(t, subRun(t, root, subJudge()), hsFail(1), aclFail(1))
	// A verification is judged at the handshake's at, not the acl's:
	// the handshake in 2020 verifies the leaf and its acl line, however
	// late, is judged on that.
	lines = []string{subStart(then, 1, subConfig(acl, caMaterial)), subAccept(then, 1), subHandshake(then, 1, "ok", false, true, chain), subACL(subAt, 1, "allow", "allow-cn"), subClose(subAt, 1, "eof")}
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	subWant(t, subRun(t, root, subJudge()))
	// With the committed PKI: the client chain is valid from 2026, so a
	// handshake of 2025 does not verify although the chain verifies now.
	before := "2025-06-01T00:00:00Z"
	lines = []string{subStart(before, 1, subConfig(acl, subCA))}
	lines = append(lines, subServed(before, 1, gtChainClient, "allow-cn")...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(1), aclFail(1))
}

// ---- minting certificates for the tests ----

// subEntity is a certificate with its key, issued by subIssue.
type subEntity struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

var subSerial int64 = 0x5000

// subIssue issues tmpl, signed by issuer (self-signed when nil), with a
// fresh P-256 key.
func subIssue(t testing.TB, tmpl *x509.Certificate, issuer *subEntity) *subEntity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subSerial++
	tmpl.SerialNumber = big.NewInt(subSerial)
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &subEntity{cert: cert, key: key, der: der}
}

// subChainDER is the chain file's content for the entities in presented
// order.
func subChainDER(ents ...*subEntity) []byte {
	var out []byte
	for _, e := range ents {
		out = append(out, e.der...)
	}
	return out
}

// subWriteChain writes der into root/chains/ under its name and returns
// the name.
func subWriteChain(t testing.TB, root string, der []byte) string {
	t.Helper()
	dir := filepath.Join(root, substanceChainsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := substanceHash(der)
	if err := os.WriteFile(filepath.Join(dir, name+".der"), der, 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// subPEM is the entities as a PEM bundle, as the proxy loads one.
func subPEM(t testing.TB, ents ...*subEntity) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range ents {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: e.der}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// subWriteCA writes the entities as a PEM bundle at dir/ca.pem, the file
// the proxy would load, and returns the start line's material entry for
// it. The bundle is not stored: what the substance rules read is the
// material store (subStoreCA), never the file.
func subWriteCA(t testing.TB, dir string, ents ...*subEntity) string {
	t.Helper()
	data := subPEM(t, ents...)
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"material":"ca","path":%q,"sha256":"%s"}`, filepath.ToSlash(p), substanceHash(data))
}

// subStoreMaterial writes data into root's material store under its
// hash, as the proxy stores a bundle it hashed for a start or reload
// line, and returns the hash.
func subStoreMaterial(t testing.TB, root string, data []byte) string {
	t.Helper()
	dir := filepath.Join(root, "material")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := substanceHash(data)
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// subStoreCA stores the entities' PEM bundle in root's material store and
// returns the start line's material entry for it: a path nothing is at,
// since the bundle is read by its hash, and the hash.
func subStoreCA(t testing.TB, root string, ents ...*subEntity) string {
	t.Helper()
	return fmt.Sprintf(`{"material":"ca","path":"/etc/gt/ca.pem","sha256":"%s"}`, subStoreMaterial(t, root, subPEM(t, ents...)))
}

// subPool is a pool of the entities.
func subPool(ents ...*subEntity) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, e := range ents {
		pool.AddCert(e.cert)
	}
	return pool
}

// ---- the rules on the leaf ----

func TestSubstanceAllowRecordedThatTheRulesDeny(t *testing.T) {
	// The other chain (CN other.example) allowed under allow-cn.
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainOther, "allow-cn"))...)
	subWant(t, subRun(t, root, subJudge()), aclFail(1))
	// Each kind, with a value the leaf does not carry.
	for _, rule := range []string{"allow-ou:dev", "allow-dns:nobody.example", "allow-ip:10.0.0.8", "allow-uri:spiffe://example.org/ns/prod/sa/*/x", "allow-uri:spiffe://other.org/**"} {
		name := strings.SplitN(rule, ":", 2)[0]
		root = subTree(t, subLines([]string{rule}, subServed(subAt, 1, gtChainClient, name))...)
		subWant(t, subRun(t, root, subJudge()), aclFail(1))
	}
}

func TestSubstanceDenyRecordedThatTheRulesAllow(t *testing.T) {
	// The client chain, verified, denied under none: the member would
	// allow it under allow-cn.
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subDenied(subAt, 1, gtChainClient))...)
	subWant(t, subRun(t, root, subJudge()), aclFail(1))
	// Refused at the handshake over a chain that verifies and matches:
	// the same finding, a deny the member would allow.
	root = subTree(t, subLines([]string{"allow-cn:client.example"}, subRefused(subAt, 1, gtChainClient))...)
	subWant(t, subRun(t, root, subJudge()), aclFail(1))
	// Under allow-all every verified chain is allowed.
	root = subTree(t, subLines([]string{"allow-all"}, subDenied(subAt, 1, gtChainOther))...)
	subWant(t, subRun(t, root, subJudge()), aclFail(1))
}

func TestSubstanceWrongRuleRecorded(t *testing.T) {
	// The client leaf carries CN client.example and OU ops: under both
	// rules the first that matches, in auth.go's order, is allow-cn.
	acl := []string{"allow-cn:client.example", "allow-ou:ops"}
	root := subTree(t, subLines(acl, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	subWant(t, subRun(t, root, subJudge()))
	root = subTree(t, subLines(acl, subServed(subAt, 1, gtChainClient, "allow-ou"))...)
	subWant(t, subRun(t, root, subJudge()), aclFail(1))
	// ou before dns, dns before ip, ip before uri.
	for _, c := range []struct {
		acl   []string
		right string
		wrong string
	}{
		{[]string{"allow-dns:client.example", "allow-ou:ops"}, "allow-ou", "allow-dns"},
		{[]string{"allow-dns:client.example", "allow-ip:10.0.0.7"}, "allow-dns", "allow-ip"},
		{[]string{"allow-ip:10.0.0.7", "allow-uri:spiffe://example.org/**"}, "allow-ip", "allow-uri"},
		{[]string{"allow-uri:spiffe://example.org/**", "policy:" + gtPolicyHash}, "allow-uri", "policy"},
	} {
		root = subTree(t, subLines(c.acl, subServed(subAt, 1, gtChainClient, c.right))...)
		subWant(t, subRun(t, root, subJudge()))
		root = subTree(t, subLines(c.acl, subServed(subAt, 1, gtChainClient, c.wrong))...)
		subWant(t, subRun(t, root, subJudge()), aclFail(1))
	}
	// A rule name the set does not hold at all.
	root = subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-all"))...)
	subWant(t, subRun(t, root, subJudge()), aclFail(1))
	// The decision alone is judged on a deny: the recorded rule name
	// is the proxy's "none", but another spelling changes nothing.
	root = subTree(t, subLines([]string{"allow-cn:client.example"}, []string{subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, true, gtChainOther), subACL(subAt, 1, "deny", "allow-cn"), subClose(subAt, 1, "refused")})...)
	subWant(t, subRun(t, root, subJudge()))
}

func TestSubstanceUnknownRuleFailsBoth(t *testing.T) {
	served := subServed(subAt, 1, gtChainClient, "allow-cn")
	denied := subDenied(subAt, 2, gtChainOther)
	for _, acl := range [][]string{
		{"allow-cn:client.example", "verify-cn:client.example"},
		{"allow-cn:client.example", "verify-hostname"},
		{"allow-cn:client.example", "disable-authentication"},
		{"allow-cn:client.example", "allow-ip:10.0.0.999"},
		{"allow-cn:client.example", "allow-uri:spiffe://a*b/c"},
		{"allow-cn:client.example", "allow-uri:spiffe://**/c"},
		{"allow-cn:client.example", "allow-spki-pin:md5:" + gtSPKIClient},
		{"allow-cn:client.example", "allow-spki-pin:sha256:" + gtSPKIClient[:62]},
		{"allow-cn:client.example", "allow-spki-pin:sha256:zz" + gtSPKIClient[2:]},
		{"allow-cn:client.example", "allow-spki-pin:" + gtSPKIClient},
	} {
		root := subTree(t, subLines(acl, served, denied)...)
		// Every verified handshake and every acl line: the set cannot be
		// evaluated, so nothing under it has been confirmed.
		subWant(t, subRun(t, root, subJudge()), hsFail(1), hsFail(2), aclFail(1), aclFail(2))
	}
}

func TestSubstanceClientModeIsNotMirrored(t *testing.T) {
	// In client mode the chain is the server's, verified by crypto/tls
	// against a server name the trace does not carry: fails closed.
	lines := []string{subStart(subAt, 1, subConfigMode("client", []string{"verify-hostname"}, subCA))}
	lines = append(lines, subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, true, gtChainClient), subACL(subAt, 1, "allow", "hostname"), subClose(subAt, 1, "eof"))
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(1), aclFail(1))
}

func TestSubstanceDisableAuthentication(t *testing.T) {
	acl := []string{"disable-authentication"}
	lines := subLines(acl,
		// No certificate asked for, allowed under the rule.
		[]string{subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, false, ""), subACL(subAt, 1, "allow", "disable-authentication"), subClose(subAt, 1, "eof")},
		// A TLS-ALPN-01 challenge probe: denied before any rule.
		[]string{subAccept(subAt, 2), subHandshake(subAt, 2, "ok", false, false, ""), subACL(subAt, 2, "deny", "acme-tls/1"), subClose(subAt, 2, "refused")},
	)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
	// A denial under any other rule, an allow under another name, and a
	// probe that presented a chain or was verified: not the proxy's.
	lines = subLines(acl,
		[]string{subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, false, ""), subACL(subAt, 1, "deny", "none"), subClose(subAt, 1, "refused")},
		[]string{subAccept(subAt, 2), subHandshake(subAt, 2, "ok", false, false, ""), subACL(subAt, 2, "allow", "allow-all"), subClose(subAt, 2, "eof")},
		[]string{subAccept(subAt, 3), subHandshake(subAt, 3, "ok", false, false, gtChainClient), subACL(subAt, 3, "deny", "acme-tls/1"), subClose(subAt, 3, "refused")},
		[]string{subAccept(subAt, 4), subHandshake(subAt, 4, "ok", false, true, ""), subACL(subAt, 4, "deny", "acme-tls/1"), subClose(subAt, 4, "refused")},
	)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1), aclFail(2), aclFail(3), hsFail(4), aclFail(4))
	// Under a rule set that asks for certificates, a probe's denial is
	// the denial of a peer that presented nothing: agreed either way.
	lines = subLines([]string{"allow-cn:client.example"},
		[]string{subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, false, ""), subACL(subAt, 1, "deny", "acme-tls/1"), subClose(subAt, 1, "refused")},
	)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
}

// ---- pins ----

func TestSubstancePins(t *testing.T) {
	pinned := []string{"allow-spki-pin:sha256:" + gtSPKIClient}
	// The pinned key, verified and allowed under the pin: agreed. The
	// other key refused (the proxy's pin check fails the handshake).
	lines := subLines(pinned, subServed(subAt, 1, gtChainClient, "allow-spki-pin"), subRefused(subAt, 2, gtChainOther))
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
	// In pin mode the chain is not verified: a pinned key under a CA the
	// bundle does not hold is agreed, and no CA material is needed.
	sum := sha256.Sum256(subLeafSPKI(t, gtChainRogue))
	rogue := []string{"allow-spki-pin:sha256:" + hex.EncodeToString(sum[:])}
	lines = []string{subStart(subAt, 1, subConfig(rogue))}
	lines = append(lines, subServed(subAt, 1, gtChainRogue, "allow-spki-pin")...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
	// Two pins, one of them sha384, either accepted.
	sum384 := sha512.Sum384(subLeafSPKI(t, gtChainOther))
	two := []string{"allow-spki-pin:sha256:" + gtSPKIClient, "allow-spki-pin:sha384:" + hex.EncodeToString(sum384[:])}
	lines = subLines(two, subServed(subAt, 1, gtChainClient, "allow-spki-pin"), subServed(subAt, 2, gtChainOther, "allow-spki-pin"))
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
	// Disagreements: the other key recorded as verified and allowed
	// under the pin; the pinned key recorded as denied; the pinned key
	// allowed under another rule's name.
	lines = subLines(pinned, subServed(subAt, 1, gtChainOther, "allow-spki-pin"), subDenied(subAt, 2, gtChainClient), subServed(subAt, 3, gtChainClient, "allow-cn"))
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(1), aclFail(1), aclFail(2), aclFail(3))
	// A verified handshake with no chain in pin mode.
	lines = subLines(pinned, []string{subAccept(subAt, 1), subHandshake(subAt, 1, "ok", false, true, ""), subACL(subAt, 1, "allow", "allow-spki-pin"), subClose(subAt, 1, "eof")})
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(1), aclFail(1))
}

// subLeafSPKI is the DER SubjectPublicKeyInfo of a committed chain's leaf.
func subLeafSPKI(t *testing.T, chain string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(gtPKI, "chains", chain+".der"))
	if err != nil {
		t.Fatal(err)
	}
	certs, err := x509.ParseCertificates(data)
	if err != nil || len(certs) == 0 {
		t.Fatalf("chain %s: %v", chain, err)
	}
	return certs[0].RawSubjectPublicKeyInfo
}

// ---- the policy ----

func TestSubstancePolicyAgreeAndDisagree(t *testing.T) {
	acl := []string{"policy:" + gtPolicyHash}
	// The policy allows CN client.example and denies the rest.
	lines := subLines(acl, subServed(subAt, 1, gtChainClient, "policy"), subDenied(subAt, 2, gtChainOther))
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
	// The other leaf allowed by the policy; the client leaf denied; the
	// client leaf allowed under a rule the set does not hold.
	lines = subLines(acl, subServed(subAt, 1, gtChainOther, "policy"), subDenied(subAt, 2, gtChainClient), subServed(subAt, 3, gtChainClient, "allow-cn"))
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1), aclFail(2), aclFail(3))
}

func TestSubstancePolicyCannotRun(t *testing.T) {
	acl := []string{"policy:" + gtPolicyHash}
	served := subServed(subAt, 1, gtChainClient, "policy")
	// No query configured: a policy rule cannot be re-judged.
	lines := subLines(acl, served)
	subWant(t, subRun(t, subTree(t, lines...), substanceJudge{}), aclFail(1))
	// The policy material absent from the start line.
	lines = append([]string{subStart(subAt, 1, subConfig(acl, subCA))}, served...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1))
	// The material's hash is not the rule's.
	lines = append([]string{subStart(subAt, 1, subConfig(acl, subCA, `{"material":"policy","path":"../testdata/pki/policy.rego","sha256":"`+gtCAHash+`"}`))}, served...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1))
	// The file on disk does not hash to the recorded hash.
	lines = append([]string{subStart(subAt, 1, subConfig(acl, subCA, `{"material":"policy","path":"../testdata/pki/ca.pem","sha256":"`+gtPolicyHash+`"}`))}, served...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1))
	// No file on disk.
	lines = append([]string{subStart(subAt, 1, subConfig(acl, subCA, `{"material":"policy","path":"../testdata/pki/absent.rego","sha256":"`+gtPolicyHash+`"}`))}, served...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(1))
	// A policy that does not compile, correctly hashed: the rule fails
	// on every line that reaches it, and not on one an earlier rule
	// decided.
	bad := filepath.Join(t.TempDir(), "bad.rego")
	if err := os.WriteFile(bad, []byte("package policy\n\nallow {\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("package policy\n\nallow {\n"))
	badHash := hex.EncodeToString(sum[:])
	badMaterial := fmt.Sprintf(`{"material":"policy","path":%q,"sha256":"%s"}`, filepath.ToSlash(bad), badHash)
	lines = []string{subStart(subAt, 1, subConfig([]string{"allow-cn:client.example", "policy:" + badHash}, subCA, badMaterial))}
	lines = append(lines, subServed(subAt, 1, gtChainClient, "allow-cn")...)
	lines = append(lines, subDenied(subAt, 2, gtChainOther)...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), aclFail(2))
	// A policy the query does not find: nothing allowed, so an allow
	// under it is a finding and a deny agrees.
	j := subJudge()
	j.PolicyQuery = "data.policy.nothing"
	lines = subLines(acl, subServed(subAt, 1, gtChainClient, "policy"), subDenied(subAt, 2, gtChainOther))
	subWant(t, subRun(t, subTree(t, lines...), j), aclFail(1))
}

// ---- reloads ----

func TestSubstanceReloadReplacesTheMaterialInForce(t *testing.T) {
	rogue, err := os.ReadFile(filepath.Join(gtPKI, "rogue-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rogue)
	rogueCA := fmt.Sprintf(`{"material":"ca","path":"../testdata/pki/rogue-ca.pem","sha256":"%s"}`, hex.EncodeToString(sum[:]))
	acl := []string{"allow-cn:client.example"}
	// Booted on the rogue CA: the client chain does not verify under it.
	// A successful reload brings the right CA: connections after it
	// verify; the one before it is still judged on the material of its
	// time.
	lines := []string{subStart(subAt, 1, subConfig(acl, rogueCA))}
	lines = append(lines, subServed(subAt, 1, gtChainClient, "allow-cn")...)
	lines = append(lines, subReload(subAt, "ok", subCA))
	lines = append(lines, subServed(subAt, 2, gtChainClient, "allow-cn")...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(1), aclFail(1))
	// A failed reload changes nothing.
	lines = []string{subStart(subAt, 1, subConfig(acl, rogueCA))}
	lines = append(lines, subReload(subAt, "failed", subCA))
	lines = append(lines, subServed(subAt, 1, gtChainClient, "allow-cn")...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(1), aclFail(1))
	// A reload that lists other material only leaves the CA as it was.
	lines = []string{subStart(subAt, 1, subConfig(acl, subCA))}
	lines = append(lines, subReload(subAt, "ok", `{"material":"cert","path":"/etc/gt/cert.pem","sha256":"`+gtCAHash+`"}`))
	lines = append(lines, subServed(subAt, 1, gtChainClient, "allow-cn")...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
}

// TestSubstanceCARotatedInPlaceByReload: a reload that rewrites the CA
// bundle at the same path unjudges nothing before it. The boot starts on
// the committed CA at a path of this test and serves the client chain; a
// successful reload records the rogue CA's hash at the same path, the
// file there now holding the rogue bundle, as on the proxy's host after
// the rotation; the rogue chain (CN client.example under the rogue CA)
// is then served, and the client chain again. The bundle each handshake
// was verified against is read from the material store by the hash in
// force at the line, never from the path: the handshake before the
// reload verifies under the replaced bundle, the rogue chain after it
// under the new one, and the client chain after it fails, since the
// rogue CA did not sign it. What the file at the path holds afterwards,
// or whether it is there at all, changes nothing. A reload that records
// a hash the store lacks judges nothing after it: every verified
// handshake under it fails, and the lines before it are as they were. A
// second cycle from memory finds the same.
func TestSubstanceCARotatedInPlaceByReload(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join(gtPKI, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := os.ReadFile(filepath.Join(gtPKI, "rogue-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	entry := func(hash string) string {
		return fmt.Sprintf(`{"material":"ca","path":%q,"sha256":"%s"}`, filepath.ToSlash(path), hash)
	}
	acl := []string{"allow-cn:client.example"}
	lines := []string{subStart(subAt, 1, subConfig(acl, entry(gtCAHash)))}
	lines = append(lines, subServed(subAt, 1, gtChainClient, "allow-cn")...)
	lines = append(lines, subReload(subAt, "ok", entry(substanceHash(rogue))))
	lines = append(lines, subServed(subAt, 2, gtChainRogue, "allow-cn")...)
	lines = append(lines, subServed(subAt, 3, gtChainClient, "allow-cn")...)
	if err := os.WriteFile(path, rogue, 0o644); err != nil {
		t.Fatal(err)
	}
	root := subTree(t, lines...)
	st := &State{}
	j := substanceJudgeFor(&Config{PolicyQuery: gtPolicyQueryPKI}, st)
	subWant(t, subRun(t, root, j), hsFail(3), aclFail(3))
	subWant(t, subRun(t, root, j), hsFail(3), aclFail(3))
	if err := os.WriteFile(path, committed, 0o644); err != nil {
		t.Fatal(err)
	}
	subWant(t, subRun(t, root, subJudge()), hsFail(3), aclFail(3))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	subWant(t, subRun(t, root, subJudge()), hsFail(3), aclFail(3))
	// A reload recording a hash the store lacks.
	unstored := substanceHash([]byte("a bundle the proxy never stored\n"))
	lines = append(lines, subReload(subAt, "ok", entry(unstored)))
	lines = append(lines, subServed(subAt, 4, gtChainClient, "allow-cn")...)
	lines = append(lines, subServed(subAt, 5, gtChainRogue, "allow-cn")...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()), hsFail(3), aclFail(3), hsFail(4), aclFail(4), hsFail(5), aclFail(5))
}

// TestSubstanceReloadOfThePolicyStartsAFreshMemory: a verdict reached
// under the policy before a reload answers for nothing after it. The boot
// allows the client chain under the committed policy, which permits it;
// a successful reload brings another policy file that denies everything;
// the same chain is then recorded as allowed under policy again. The
// member must fail acl-substance on the second line although it
// remembered the chain's verdict from the first: the memory is keyed on
// the policy hash in force at the line, and the rules' verdict under the
// replaced policy is not consulted.
func TestSubstanceReloadOfThePolicyStartsAFreshMemory(t *testing.T) {
	denyAll := []byte("package policy\n\ndefault allow = false\n")
	denyPath := filepath.Join(t.TempDir(), "deny.rego")
	if err := os.WriteFile(denyPath, denyAll, 0o644); err != nil {
		t.Fatal(err)
	}
	denyHash := substanceHash(denyAll)
	denyPolicy := fmt.Sprintf(`{"material":"policy","path":%q,"sha256":"%s"}`, filepath.ToSlash(denyPath), denyHash)
	acl := []string{"policy:" + gtPolicyHash}
	lines := []string{subStart(subAt, 1, subConfig(acl, subCA, subPolicy))}
	lines = append(lines, subServed(subAt, 1, gtChainClient, "policy")...)
	lines = append(lines, subReload(subAt, "ok", denyPolicy))
	lines = append(lines, subServed(subAt, 2, gtChainClient, "policy")...)
	root := subTree(t, lines...)
	st := &State{}
	j := substanceJudgeFor(&Config{PolicyQuery: gtPolicyQueryPKI}, st)
	subWant(t, subRun(t, root, j), aclFail(2))
	// The first line's verdict is remembered under the policy it was
	// reached with; nothing is remembered under the policy that
	// replaced it, whose evaluation the second line failed on.
	before := gtChainClient + "\x00" + "policy:" + gtPolicyHash + "\x00" + gtPolicyHash + "\x00" + gtPolicyQueryPKI
	if rule, ok := st.Substance.rules[before]; !ok || rule != "policy" {
		t.Fatalf("the verdict before the reload is not remembered under its policy: %q, %v; keys %v", rule, ok, st.Substance.rules)
	}
	after := gtChainClient + "\x00" + "policy:" + gtPolicyHash + "\x00" + denyHash + "\x00" + gtPolicyQueryPKI
	if rule, ok := st.Substance.rules[after]; ok {
		t.Fatalf("a verdict %q remembered under the policy brought by the reload", rule)
	}
	// A second cycle over the same bytes, from memory, finds the same.
	subWant(t, subRun(t, root, j), aclFail(2))
	// A reload that keeps the policy's hash keeps the memory: the same
	// bytes at another path are the same policy.
	samePath := filepath.Join(t.TempDir(), "same.rego")
	committed, err := os.ReadFile(filepath.Join(gtPKI, "policy.rego"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(samePath, committed, 0o644); err != nil {
		t.Fatal(err)
	}
	samePolicy := fmt.Sprintf(`{"material":"policy","path":%q,"sha256":"%s"}`, filepath.ToSlash(samePath), gtPolicyHash)
	lines = []string{subStart(subAt, 1, subConfig(acl, subCA, subPolicy))}
	lines = append(lines, subServed(subAt, 1, gtChainClient, "policy")...)
	lines = append(lines, subReload(subAt, "ok", samePolicy))
	lines = append(lines, subServed(subAt, 2, gtChainClient, "policy")...)
	subWant(t, subRun(t, subTree(t, lines...), subJudge()))
}

// ---- the memory ----

func TestSubstanceCacheWindowAndReset(t *testing.T) {
	acl := []string{"allow-cn:client.example"}
	root := subTree(t, subLines(acl, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	st := &State{}
	cfg := &Config{PolicyQuery: gtPolicyQueryPKI}
	j := substanceJudgeFor(cfg, st)
	subWant(t, subRun(t, root, j))
	cache := st.Substance
	if cache == nil || cache.Boot != 1 {
		t.Fatalf("no memory kept for boot 1: %+v", cache)
	}
	// The verification is remembered under (chain hash, CA hash) with
	// the window every certificate of the verified chain is valid in:
	// the test PKI's 2026-01-01 to 2036-01-01.
	key := gtChainClient + ":" + gtCAHash
	w, ok := cache.chains[key]
	if !ok {
		t.Fatalf("no window remembered under %s: %v", key, cache.chains)
	}
	if w.NotBefore != time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) || w.NotAfter != time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("window %v", w)
	}
	// Nothing else is under a size or a time: every key is a hash or
	// hashes joined.
	for k := range cache.chains {
		for _, part := range strings.Split(k, ":") {
			if !substanceReChainName.MatchString(part) {
				t.Errorf("chain key part %q is not a hash", part)
			}
		}
	}
	// A refusal is not a verification: nothing under the rogue chain in
	// the windows. It is remembered on its own, under the chain, the CA
	// and the recorded second.
	root2 := subTree(t, subLines(acl, subServed(subAt, 1, gtChainRogue, "allow-cn"))...)
	subWant(t, subRun(t, root2, j), hsFail(1), aclFail(1))
	if _, ok := cache.chains[gtChainRogue+":"+gtCAHash]; ok {
		t.Fatal("a refusal was remembered as a verification")
	}
	at, _ := time.Parse(time.RFC3339, subAt)
	refusedKey := gtChainRogue + ":" + gtCAHash + ":" + strconv.FormatInt(at.Unix(), 10)
	if _, ok := cache.refused[refusedKey]; !ok {
		t.Fatalf("the refusal was not remembered under %s: %v", refusedKey, cache.refused)
	}
	for k := range cache.refused {
		parts := strings.Split(k, ":")
		if len(parts) != 3 || !substanceReChainName.MatchString(parts[0]) || !substanceReChainName.MatchString(parts[1]) || parts[2] != strconv.FormatInt(at.Unix(), 10) {
			t.Errorf("refusal key %q is not (chain hash, CA hash, second)", k)
		}
	}
	// The refusal memory is consulted: a refusal planted under the client
	// chain's key at the handshake's second answers for it and the chain
	// that verifies is refused; at another second it is not consulted.
	delete(cache.chains, key)
	cache.refused[gtChainClient+":"+gtCAHash+":"+strconv.FormatInt(at.Unix(), 10)] = struct{}{}
	subWant(t, subRun(t, root, j), hsFail(1), aclFail(1))
	delete(cache.refused, gtChainClient+":"+gtCAHash+":"+strconv.FormatInt(at.Unix(), 10))
	cache.refused[gtChainClient+":"+gtCAHash+":"+strconv.FormatInt(at.Unix()+1, 10)] = struct{}{}
	subWant(t, subRun(t, root, j))
	delete(cache.refused, gtChainClient+":"+gtCAHash+":"+strconv.FormatInt(at.Unix()+1, 10))
	// The memory is consulted: a window planted under the rogue chain's
	// key that covers the handshake's time answers for it; one that
	// does not cover it is not consulted and the chain is verified
	// again, and refused. The window is read before the refusal memory.
	cache.chains[gtChainRogue+":"+gtCAHash] = substanceWindow{NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour)}
	subWant(t, subRun(t, root2, j))
	cache.chains[gtChainRogue+":"+gtCAHash] = substanceWindow{NotBefore: at.Add(time.Second), NotAfter: at.Add(time.Hour)}
	subWant(t, subRun(t, root2, j), hsFail(1), aclFail(1))
	cache.chains[gtChainRogue+":"+gtCAHash] = substanceWindow{NotBefore: at.Add(-time.Hour), NotAfter: at.Add(-time.Second)}
	subWant(t, subRun(t, root2, j), hsFail(1), aclFail(1))
	// The CA's hash is part of the key: the same chain under another
	// bundle is verified afresh.
	if _, ok := cache.chains[gtChainClient+":"+gtPolicyHash]; ok {
		t.Fatal("a key without the CA hash")
	}
	// The rules' verdict is remembered under the chain, the set, the
	// policy hash and the query, and the memory is consulted.
	rkey := gtChainClient + "\x00" + "allow-cn:client.example" + "\x00" + "" + "\x00" + gtPolicyQueryPKI
	if rule, ok := cache.rules[rkey]; !ok || rule != "allow-cn" {
		t.Fatalf("rule verdict under %q: %q, %v; keys %v", rkey, rule, ok, cache.rules)
	}
	cache.rules[rkey] = "allow-ou"
	subWant(t, subRun(t, root, j), aclFail(1))
	// A boot change empties everything.
	lines := []string{subStart(subAt, 2, subConfig(acl, subCA))}
	lines = append(lines, subServed(subAt, 1, gtChainClient, "allow-cn")...)
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(tRenumberLines(lines)...))
	subWant(t, subRun(t, root, j))
	if cache.Boot != 2 || len(cache.chains) != 1 || len(cache.rules) != 1 || len(cache.refused) != 0 {
		t.Fatalf("memory after the boot change: boot %d, chains %v, rules %v, refused %v", cache.Boot, cache.chains, cache.rules, cache.refused)
	}
	if _, ok := cache.rules[rkey]; !ok || cache.rules[rkey] != "allow-cn" {
		t.Fatalf("the planted verdict survived the boot change: %v", cache.rules)
	}
}

func TestSubstancePolicyCompilationIsRemembered(t *testing.T) {
	acl := []string{"policy:" + gtPolicyHash}
	root := subTree(t, subLines(acl, subServed(subAt, 1, gtChainClient, "policy"))...)
	st := &State{}
	j := substanceJudgeFor(&Config{PolicyQuery: gtPolicyQueryPKI}, st)
	subWant(t, subRun(t, root, j))
	key := gtPolicyHash + ":" + gtPolicyQueryPKI
	pol, ok := st.Substance.policies[key]
	if !ok || pol.query == nil || pol.err != nil {
		t.Fatalf("policy not remembered under %q: %+v", key, pol)
	}
	// A compilation error is a function of the bytes and is remembered
	// too; the memory is consulted (once the leaf's own verdict, which
	// is remembered ahead of it, is forgotten).
	st.Substance.policies[key] = &substancePolicy{err: os.ErrInvalid}
	st.Substance.rules = map[string]string{}
	subWant(t, subRun(t, root, j), aclFail(1))
}

// ---- the surface ----

func TestSubstanceIsJudgedForSurfaceDisagree(t *testing.T) {
	// A member computing a substance finding the tunnel member did not
	// publish disagrees with it, on both identifiers.
	root := subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainRogue, "allow-cn"))...)
	boot, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, subAt)
	peers := map[string]PeerView{surfaceTunnel: {Verdict: VerdictAlive, Checks: surfaceIdentifiers(surfaceTunnel)}}
	got := surfaceDisagreements("super", boot, true, now, surfaceMargins{}, subJudge(), peers)
	want := []Finding{{checkSurfaceDisagree, "tunnel:" + checkHandshakeSubstance}, {checkSurfaceDisagree, "tunnel:" + checkACLSubstance}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Published: agreed.
	pv := peers[surfaceTunnel]
	pv.FaultPresent, pv.FaultParsed = true, true
	pv.Failing = []Finding{{checkHandshakeSubstance, "1"}, {checkACLSubstance, "1"}}
	peers[surfaceTunnel] = pv
	if got := surfaceDisagreements("super", boot, true, now, surfaceMargins{}, subJudge(), peers); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	// Not listed by the owner: disagreed whatever the trace says.
	peers[surfaceTunnel] = PeerView{Verdict: VerdictAlive, Checks: []string{"conn-consistent", "handshake-verified", "resumption-verified", "acl-before-serve", "lifetime-cap", "accept-loop"}}
	root = subTree(t, subLines([]string{"allow-cn:client.example"}, subServed(subAt, 1, gtChainClient, "allow-cn"))...)
	if boot, err = gtReadLatest(root); err != nil {
		t.Fatal(err)
	}
	got = surfaceDisagreements("super", boot, true, now, surfaceMargins{}, subJudge(), peers)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSubstanceIdentifiersAreTheSurfaces(t *testing.T) {
	ids := strings.Join(tunnelSurfaceIdentifiers, ",")
	if !strings.HasSuffix(ids, ","+checkHandshakeSubstance+","+checkACLSubstance) {
		t.Fatalf("the surface's identifiers do not end in the substance rules: %s", ids)
	}
	if checkHandshakeSubstance != "handshake-substance" || checkACLSubstance != "acl-substance" {
		t.Fatalf("identifiers %q %q", checkHandshakeSubstance, checkACLSubstance)
	}
}
