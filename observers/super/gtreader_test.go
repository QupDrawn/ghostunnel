package main

// gtreader_test.go proves this member's reader of gt/ against every rule of
// ringtrace/README.md section 1.4, on trees written by hand in the exact
// format. Nothing here imports ringtrace. Every member carries a
// byte-identical copy of this file.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// gtLines are lines of one healthy boot, in order, without line feeds.
var gtLines = []string{
	`{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"localhost:8443","target":"localhost:8080","proxy_protocol":"off","status_listen":"127.0.0.1:6060","status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":300,"sandbox_state":"applied","sandbox_accepted":null,"material":[{"material":"cert","path":"/etc/gt/cert.pem","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},{"material":"key","path":"/etc/gt/key.pem","sha256":null},{"material":"ca","path":"../testdata/pki/ca.pem","sha256":"89b996c9c451ea98bdfeaf5827ed15e69c9f5a5d109b032c8142f7f724810cf2"}],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
	`{"kind":"accept","version":1,"sequence":2,"at":"2026-09-24T11:00:01Z","conn":1,"listener":"127.0.0.1:8443","remote":"10.0.0.7:51000"}`,
	`{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T11:00:01Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":{"subject":"CN=client","issuer":"CN=ca","serial":"0a","sans":["dns:client.example","uri:spiffe://x/y"],"fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"error":null,"chain":"6cfe43984b110c899018930dcd57ba56d99193d0cbf49804ec32622750ad3714"}`,
	`{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"allow-cn","reason":"cn matched"}`,
	`{"kind":"close","version":1,"sequence":5,"at":"2026-09-24T11:00:09Z","conn":1,"reason":"eof","duration_ms":8000}`,
	`{"kind":"reload","version":1,"sequence":6,"at":"2026-09-24T11:01:00Z","outcome":"ok","error":null,"serving":true,"material":[]}`,
	`{"kind":"shutdown","version":1,"sequence":7,"at":"2026-09-24T11:02:00Z","source":"signal","authorized":true,"peer":null,"detail":"SIGTERM"}`,
	`{"kind":"tick","version":1,"sequence":8,"at":"2026-09-24T11:02:05Z"}`,
	`{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"accept tcp 127.0.0.1:8443: too many open files","backoff_ms":5}`,
}

// gtPKI is the committed test PKI (observers/testdata/pki, made by
// testdata/tools/substancepki; hashes.txt there is the source of every
// hash quoted here): the CA bundle gtLines's start line names, relative
// to the package directory go test runs in, and the chains the substance
// rules (substance.go) read under gt/chains/.
const (
	gtPKI            = `../testdata/pki`
	gtCAHash         = "89b996c9c451ea98bdfeaf5827ed15e69c9f5a5d109b032c8142f7f724810cf2"
	gtPolicyHash     = "259219f98e0aa3e48f9b56670c074139377b57a9297fea3ed9e57ce51076ad6c"
	gtChainClient    = "6cfe43984b110c899018930dcd57ba56d99193d0cbf49804ec32622750ad3714" // CN client.example, via the intermediate
	gtChainOther     = "88ec9b6db56328b5cbcb0c0a632df0d4c5b0c83a2d01bea306cc498b63833175" // CN other.example, by the CA
	gtChainRogue     = "3e05e8d89f0700d627a7bd7a9cd47ff2cbfda251e7eca2125e13c2bf7e22c716" // CN client.example, by a CA the bundle does not hold
	gtChainExpired   = "179af4581da0c1e063492a010f5acda684d8121fce433e2945c212f7749d61d2" // CN client.example, valid in 2020 only
	gtSPKIClient     = "c8a5488ed95204c189f91e84b24b3abc918b675d086a0c39fe22cd6045879225"
	gtSPKIOther      = "eabeaebbd0c5453638aba2044a184d99b6f763a0316c0567910b4af640e4f8e6"
	gtPolicyQueryPKI = "data.policy.allow"
)

// gtWriteSegment writes raw bytes as one segment of a boot directory, and
// installs the test PKI's chain store and material store beside the boots
// (gtInstallChains, gtInstallMaterial), as the proxy's trace root carries
// them: every tree a test writes is a root the substance rules can read
// chains and CA bundles from.
func gtWriteSegment(t *testing.T, root, boot, segment string, data []byte) {
	t.Helper()
	dir := filepath.Join(root, boot)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, segment), data, 0o644); err != nil {
		t.Fatal(err)
	}
	gtInstallChains(t, root)
	gtInstallMaterial(t, root)
}

// gtInstallMaterial copies the test PKI's CA bundles, ca.pem and
// rogue-ca.pem, into root/material/ under their hashes, as the proxy
// stores the bundle every start and reload line hashes, leaving one
// already there as it is.
func gtInstallMaterial(t testing.TB, root string) {
	t.Helper()
	dir := filepath.Join(root, "material")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.pem", "rogue-ca.pem"} {
		b, err := os.ReadFile(filepath.Join(gtPKI, name))
		if err != nil {
			t.Fatalf("the test PKI is not at %s: %v", gtPKI, err)
		}
		target := filepath.Join(dir, substanceHash(b))
		if _, err := os.Stat(target); err == nil {
			continue
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// gtInstallChains copies every chain of the test PKI into root/chains/,
// leaving one already there as it is.
func gtInstallChains(t testing.TB, root string) {
	t.Helper()
	dir := filepath.Join(root, "chains")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(gtPKI, "chains"))
	if err != nil {
		t.Fatalf("the test PKI is not at %s: %v", gtPKI, err)
	}
	for _, e := range entries {
		target := filepath.Join(dir, e.Name())
		if _, err := os.Stat(target); err == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(gtPKI, "chains", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// gtJoin makes segment bytes of complete lines.
func gtJoin(lines ...string) []byte {
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// gtOneBoot writes one boot with one segment of the given lines and returns
// the root.
func gtOneBoot(t *testing.T, lines ...string) string {
	t.Helper()
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines...))
	return root
}

func TestGTReadHealthyBoot(t *testing.T) {
	root := gtOneBoot(t, gtLines...)
	b, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Number != 1 || b.Torn || len(b.Records) != 9 {
		t.Fatalf("boot %d torn=%v records=%d", b.Number, b.Torn, len(b.Records))
	}
	kinds := []string{"start", "accept", "handshake", "acl", "close", "reload", "shutdown", "tick", "accept-error"}
	for i, r := range b.Records {
		if r.Kind != kinds[i] || r.Sequence != int64(i+1) {
			t.Fatalf("record %d: kind %s sequence %d", i, r.Kind, r.Sequence)
		}
	}
	st := b.Records[0].Start
	if st == nil || st.Boot != 1 || st.PID != 4242 || st.Config.Listen != "localhost:8443" || !st.Config.VerifyOnResume || st.Config.LifetimeCapSeconds != 300 || !st.Config.PprofCmdlineRedacted || !st.Config.ShutdownRequiresClientCert {
		t.Fatalf("start decoded wrongly: %+v", st)
	}
	if st.Config.SandboxState != "applied" || st.Config.SandboxAccepted != nil {
		t.Fatalf("sandbox decoded wrongly: %+v", st.Config)
	}
	if len(st.Config.Material) != 3 || st.Config.Material[0].SHA256 == nil || st.Config.Material[1].SHA256 != nil || st.Config.Material[2].Material != "ca" || st.Config.Material[2].SHA256 == nil || *st.Config.Material[2].SHA256 != gtCAHash {
		t.Fatalf("material decoded wrongly: %+v", st.Config.Material)
	}
	if st.Config.StatusListen == nil || *st.Config.StatusListen != "127.0.0.1:6060" {
		t.Fatalf("status_listen decoded wrongly")
	}
	hs := b.Records[2].Handshake
	if hs == nil || hs.Peer == nil || len(hs.Peer.SANs) != 2 || hs.Error != nil || !hs.Verified {
		t.Fatalf("handshake decoded wrongly: %+v", hs)
	}
	if hs.Chain != gtChainClient {
		t.Fatalf("chain decoded wrongly: %q", hs.Chain)
	}
	if b.Records[4].Close.DurationMS != 8000 || b.Records[6].Shutdown.Source != "signal" || b.Records[5].Reload.Outcome != "ok" {
		t.Fatalf("bodies decoded wrongly")
	}
	if strings.Join(st.Config.ACL, ",") != "allow-cn:client.example" {
		t.Fatalf("acl decoded wrongly: %q", st.Config.ACL)
	}
	if tick := b.Records[7]; tick.Kind != "tick" || tick.Start != nil || tick.AcceptError != nil {
		t.Fatalf("tick decoded wrongly: %+v", tick)
	}
	ae := b.Records[8].AcceptError
	if ae == nil || ae.Error != "accept tcp 127.0.0.1:8443: too many open files" || ae.BackoffMS != 5 {
		t.Fatalf("accept-error decoded wrongly: %+v", ae)
	}
}

// TestGTClassify pins the marker rule (README 1.1): the marker includes the
// closing quote and comma, so accept never prefix-matches accept-error, and
// the ten kinds are the emitter's, in its order.
func TestGTClassify(t *testing.T) {
	want := []string{"start", "accept", "handshake", "acl", "close", "reload", "shutdown", "tick", "accept-error", "refusal"}
	if strings.Join(gtKinds, ",") != strings.Join(want, ",") {
		t.Fatalf("kinds %v, want %v", gtKinds, want)
	}
	for i, line := range gtLines {
		if got := gtClassify([]byte(line)); got != want[i] {
			t.Errorf("line %d classified as %q, want %q", i+1, got, want[i])
		}
	}
	for _, line := range []string{`{"kind":"accept-errorx","version":1`, `{"kind":"accept","version":1`, `{"kind":"tickle",`, `{"kind":"tick"`} {
		got := gtClassify([]byte(line))
		switch line {
		case `{"kind":"accept","version":1`:
			if got != "accept" {
				t.Errorf("%s classified as %q", line, got)
			}
		default:
			if got != "" {
				t.Errorf("%s classified as %q, want none", line, got)
			}
		}
	}
}

// TestGTDecodeACL pins config.acl (README 1.2): the closed vocabulary, a
// non-empty value after every prefix, a hash after policy, strictly
// ascending byte order.
func TestGTDecodeACL(t *testing.T) {
	line := func(acl string) string {
		return `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":` + acl + `,"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`
	}
	hash := strings.Repeat("ab", 32)
	good := []string{
		`["allow-all"]`,
		`["verify-hostname"]`,
		`["disable-authentication"]`,
		`["allow-cn:a","allow-cn:b","allow-dns:x.example","allow-ip:10.0.0.1","allow-ou:o","allow-uri:spiffe://x/*","policy:` + hash + `"]`,
		`["allow-spki-pin:sha256:` + hash + `"]`,
		`["verify-cn:a","verify-dns:d","verify-ip:i","verify-ou:o","verify-spki-pin:p","verify-uri:u"]`,
		`["allow-cn:a","allow-cn:a:b"]`,
	}
	for _, acl := range good {
		rec, err := gtDecodeLine([]byte(line(acl)))
		if err != nil {
			t.Errorf("acl %s: %v", acl, err)
			continue
		}
		var want []string
		if err := json.Unmarshal([]byte(acl), &want); err != nil {
			t.Fatal(err)
		}
		if strings.Join(rec.Start.Config.ACL, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("acl %s decoded as %q", acl, rec.Start.Config.ACL)
		}
	}
	bad := map[string]string{
		"null":                  `null`,
		"empty":                 `[]`,
		"not an array":          `"allow-all"`,
		"element not a string":  `[1]`,
		"element null":          `[null]`,
		"unknown token":         `["allow-everything"]`,
		"token with a value":    `["allow-all:x"]`,
		"prefix without value":  `["allow-cn:"]`,
		"prefix alone":          `["allow-cn"]`,
		"policy not a hash":     `["policy:abc"]`,
		"policy upper-case":     `["policy:` + strings.ToUpper(hash) + `"]`,
		"unsorted":              `["allow-cn:b","allow-cn:a"]`,
		"duplicate":             `["allow-cn:a","allow-cn:a"]`,
		"token after prefix":    `["verify-hostname","allow-all"]`,
		"pem in a rule":         `["allow-cn:-----BEGIN X"]`,
		"case of the token":     `["Allow-All"]`,
		"whitespace in a token": `[" allow-all"]`,
	}
	for name, acl := range bad {
		if _, err := gtDecodeLine([]byte(line(acl))); err == nil {
			t.Errorf("%s: acl %s decoded", name, acl)
		}
	}
	// The vocabulary is pinned to the README's, in its order.
	if strings.Join(gtACLTokens, ",") != "allow-all,verify-hostname,disable-authentication" {
		t.Errorf("tokens %v", gtACLTokens)
	}
	if strings.Join(gtACLPrefixes, ",") != "allow-cn:,allow-ou:,allow-dns:,allow-ip:,allow-uri:,allow-spki-pin:,verify-cn:,verify-ou:,verify-dns:,verify-ip:,verify-uri:,verify-spki-pin:,policy:" {
		t.Errorf("prefixes %v", gtACLPrefixes)
	}
	// gtACLRuleValid is the same rule, for a flag parser to refuse an
	// expectation the trace could never carry.
	for _, rule := range []string{"allow-all", "allow-cn:a", "policy:" + hash} {
		if err := gtACLRuleValid(rule); err != nil {
			t.Errorf("gtACLRuleValid(%q): %v", rule, err)
		}
	}
	for _, rule := range []string{"", "allow-cn:", "allow-cn", "policy:x", "nope", "allow-all "} {
		if err := gtACLRuleValid(rule); err == nil {
			t.Errorf("gtACLRuleValid(%q) accepted", rule)
		}
	}
}

func TestGTReadsHighestBootAcrossSegments(t *testing.T) {
	root := t.TempDir()
	// Boot 1 is malformed on purpose: the reader must never open it.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", []byte("garbage\n"))
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(strings.Replace(gtLines[0], `"boot":1`, `"boot":2`, 1), gtLines[1], gtLines[2]))
	gtWriteSegment(t, root, "0000000002", "0000000004.trace", gtJoin(gtLines[3], gtLines[4]))
	// A torn final line in the last segment is ignored and reported.
	gtWriteSegment(t, root, "0000000002", "0000000006.trace", append(gtJoin(gtLines[5]), []byte(`{"kind":"shutdown","version":1,"sequence":7,"at":"2026-09-24T11:02:00Z","source":"sig`)...))
	b, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Number != 2 || len(b.Records) != 6 || !b.Torn {
		t.Fatalf("boot %d records=%d torn=%v", b.Number, len(b.Records), b.Torn)
	}
}

func TestGTEmptyBootAndEmptyLastSegmentAreBenign(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "0000000003"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := gtReadLatest(root)
	if err != nil || b.Number != 3 || len(b.Records) != 0 {
		t.Fatalf("empty boot: %v %+v", err, b)
	}
	root = t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:3]...))
	gtWriteSegment(t, root, "0000000001", "0000000004.trace", nil)
	b, err = gtReadLatest(root)
	if err != nil || len(b.Records) != 3 || b.Torn {
		t.Fatalf("empty last segment: %v %+v", err, b)
	}
}

func TestGTRootFailures(t *testing.T) {
	if _, err := gtReadLatest(""); err == nil || gtSubject(err) != "gt" {
		t.Fatalf("no root: %v", err)
	}
	if _, err := gtReadLatest(filepath.Join(t.TempDir(), "missing")); err == nil || gtSubject(err) != "gt" {
		t.Fatalf("missing root: %v", err)
	}
	if _, err := gtReadLatest(t.TempDir()); err == nil || gtSubject(err) != "gt" {
		t.Fatalf("no boot: %v", err)
	}
	root := gtOneBoot(t, gtLines...)
	if err := os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := gtReadLatest(root); err == nil || gtSubject(err) != "stray" {
		t.Fatalf("stray file under root: %v", err)
	}
	root = gtOneBoot(t, gtLines...)
	if err := os.Mkdir(filepath.Join(root, "boot-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := gtReadLatest(root); err == nil || gtSubject(err) != "boot-1" {
		t.Fatalf("misnamed directory under root: %v", err)
	}
	// The emitter's lock (README 1.3) is the one permitted non-boot entry:
	// a regular file named lock, whatever its content.
	root = gtOneBoot(t, gtLines...)
	if err := os.WriteFile(filepath.Join(root, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := gtReadLatest(root); err != nil || len(b.Records) != len(gtLines) {
		t.Fatalf("lock file under root: %v %+v", err, b)
	}
	if err := os.WriteFile(filepath.Join(root, "lock"), []byte("held\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := gtReadLatest(root); err != nil {
		t.Fatalf("lock file with content under root: %v", err)
	}
	// Anything else at that name is not the lock.
	root = gtOneBoot(t, gtLines...)
	if err := os.Mkdir(filepath.Join(root, "lock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := gtReadLatest(root); err == nil || gtSubject(err) != "lock" {
		t.Fatalf("directory named lock under root: %v", err)
	}
	// And a lock beside a stray is still a stray.
	root = gtOneBoot(t, gtLines...)
	for _, name := range []string{"lock", "lock.tmp"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := gtReadLatest(root); err == nil || gtSubject(err) != "lock.tmp" {
		t.Fatalf("stray beside the lock: %v", err)
	}
}

func TestGTBootFailures(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T, root string)
		subject string
	}{
		{"stray entry in boot", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
			gtWriteSegment(t, root, "0000000001", "notes.txt", []byte("x"))
		}, "0000000001/notes.txt"},
		{"first segment misnamed", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000002.trace", gtJoin(gtLines...))
		}, "0000000001/0000000002.trace"},
		{"segment gap", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:3]...))
			gtWriteSegment(t, root, "0000000001", "0000000005.trace", gtJoin(gtLines[4:]...))
		}, "0000000001/0000000005.trace"},
		{"torn line in a non-last segment", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", append(gtJoin(gtLines[:3]...), []byte(`{"kind":"acl",`)...))
			gtWriteSegment(t, root, "0000000001", "0000000004.trace", gtJoin(gtLines[3:]...))
		}, "0000000001/0000000001.trace:4"},
		{"empty non-last segment", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", nil)
			gtWriteSegment(t, root, "0000000001", "0000000002.trace", gtJoin(gtLines...))
		}, "0000000001/0000000001.trace"},
		{"sequence gap within a segment", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[0], gtLines[2]))
		}, "0000000001/0000000001.trace:2"},
		{"sequence repeated", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[0], gtLines[1], gtLines[1]))
		}, "0000000001/0000000001.trace:3"},
		{"first line not a start", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(strings.Replace(gtLines[1], `"sequence":2`, `"sequence":1`, 1)))
		}, "0000000001/0000000001.trace:1"},
		{"start names another boot", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(gtLines...))
		}, "0000000002/0000000001.trace:1"},
		{"second start line", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[0], strings.Replace(gtLines[0], `"sequence":1`, `"sequence":2`, 1)))
		}, "0000000001/0000000001.trace:2"},
		{"timestamp goes back", func(t *testing.T, root string) {
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[0], strings.Replace(gtLines[1], "11:00:01Z", "10:59:59Z", 1)))
		}, "0000000001/0000000001.trace:2"},
		{"unreadable segment", func(t *testing.T, root string) {
			if err := os.MkdirAll(filepath.Join(root, "0000000001", "0000000001.trace"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "0000000001/0000000001.trace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			c.build(t, root)
			b, err := gtReadLatest(root)
			if err == nil {
				t.Fatalf("read succeeded: %+v", b)
			}
			if got := gtSubject(err); got != c.subject {
				t.Fatalf("subject %q, want %q (%v)", got, c.subject, err)
			}
		})
	}
}

// TestGTDecodeLineRejects is every malformation of one line under README
// 1.1 and 1.2 that the healthy lines can be mutated into.
func TestGTDecodeLineRejects(t *testing.T) {
	long := `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"allow-cn","reason":"` + strings.Repeat("x", 65536) + `"}`
	cases := map[string]string{
		"no marker":                             `{"version":1,"kind":"acl","sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"space in marker":                       `{"kind": "acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"unknown kind":                          `{"kind":"hello","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z"}`,
		"unknown key":                           `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":"","extra":1}`,
		"missing key":                           `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r"}`,
		"duplicate key":                         `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"conn":1,"decision":"allow","rule":"r","reason":""}`,
		"bytes after object":                    `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""} `,
		"carriage return":                       `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}` + "\r",
		"version 2":                             `{"kind":"acl","version":2,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"version as string":                     `{"kind":"acl","version":"1","sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"sequence as float":                     `{"kind":"acl","version":1,"sequence":4.0,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"sequence zero":                         `{"kind":"acl","version":1,"sequence":0,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"timestamp with offset":                 `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01+00:00","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"timestamp with fraction":               `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01.5Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"timestamp not a date":                  `{"kind":"acl","version":1,"sequence":4,"at":"2026-13-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`,
		"enum outside set":                      `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"maybe","rule":"r","reason":""}`,
		"rule empty":                            `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"","reason":""}`,
		"conn zero":                             `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":0,"decision":"allow","rule":"r","reason":""}`,
		"null where not nullable":               `{"kind":"acl","version":1,"sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":null}`,
		"boolean as string":                     `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T11:00:01Z","conn":1,"outcome":"ok","resumed":"false","verified":true,"protocol":"","peer":null,"error":null}`,
		"peer with unknown key":                 `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T11:00:01Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"","peer":{"subject":"","issuer":"","serial":"","sans":[],"fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","x":1},"error":null}`,
		"peer sans null":                        `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T11:00:01Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"","peer":{"subject":"","issuer":"","serial":"","sans":null,"fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"error":null}`,
		"peer san without prefix":               `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T11:00:01Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"","peer":{"subject":"","issuer":"","serial":"","sans":["client.example"],"fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"error":null}`,
		"fingerprint upper-case":                `{"kind":"handshake","version":1,"sequence":3,"at":"2026-09-24T11:00:01Z","conn":1,"outcome":"ok","resumed":false,"verified":true,"protocol":"","peer":{"subject":"","issuer":"","serial":"","sans":[],"fingerprint":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"},"error":null}`,
		"pem in a field":                        `{"kind":"shutdown","version":1,"sequence":7,"at":"2026-09-24T11:02:00Z","source":"signal","authorized":true,"peer":null,"detail":"-----BEGIN RSA PRIVATE KEY-----"}`,
		"pem escaped in a field":                `{"kind":"shutdown","version":1,"sequence":7,"at":"2026-09-24T11:02:00Z","source":"signal","authorized":true,"peer":null,"detail":"-----BEGIN X"}`,
		"key material with a hash":              `{"kind":"reload","version":1,"sequence":6,"at":"2026-09-24T11:01:00Z","outcome":"ok","error":null,"serving":true,"material":[{"material":"key","path":"/k","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}`,
		"material null":                         `{"kind":"reload","version":1,"sequence":6,"at":"2026-09-24T11:01:00Z","outcome":"ok","error":null,"serving":true,"material":null}`,
		"material kind outside set":             `{"kind":"reload","version":1,"sequence":6,"at":"2026-09-24T11:01:00Z","outcome":"ok","error":null,"serving":true,"material":[{"material":"crl","path":"/c","sha256":null}]}`,
		"config missing key":                    `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":300,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config listen empty":                   `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":300,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config lifetime cap negative":          `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":-1,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config as null":                        `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":null}`,
		"config without the admin fields":       `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":300,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"admin field as null":                   `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":null,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":300,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"pid zero":                              `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":0,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config with the old landlock key":      `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"landlock":true,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config landlock beside the sandbox":    `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"landlock":true,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_state outside set":      `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"enforced","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_state as boolean":       `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":true,"sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_state null":             `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":null,"sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_accepted missing":       `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"applied","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_accepted empty":         `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"unsupported","sandbox_accepted":"","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_accepted as boolean":    `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"unsupported","sandbox_accepted":true,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_accepted with applied":  `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":"linux","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_accepted with disabled": `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"disabled","sandbox_accepted":"linux","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_accepted with failed":   `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"failed","sandbox_accepted":"linux","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config sandbox_accepted with skipped":  `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"skipped","sandbox_accepted":"linux","material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"duration negative":                     `{"kind":"close","version":1,"sequence":5,"at":"2026-09-24T11:00:09Z","conn":1,"reason":"eof","duration_ms":-1}`,
		"accept remote empty":                   `{"kind":"accept","version":1,"sequence":2,"at":"2026-09-24T11:00:01Z","conn":1,"listener":"l","remote":""}`,
		"shutdown source outside set":           `{"kind":"shutdown","version":1,"sequence":7,"at":"2026-09-24T11:02:00Z","source":"console","authorized":true,"peer":null,"detail":""}`,
		"line too long":                         long,
		"config with the old key set (no acl)":  `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config acl empty":                      `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":[],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"config acl unsorted":                   `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["policy:0000000000000000000000000000000000000000000000000000000000000000","allow-all"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`,
		"tick with a body key":                  `{"kind":"tick","version":1,"sequence":8,"at":"2026-09-24T11:02:05Z","conn":1}`,
		"tick with an error key":                `{"kind":"tick","version":1,"sequence":8,"at":"2026-09-24T11:02:05Z","error":"x"}`,
		"tick without at":                       `{"kind":"tick","version":1,"sequence":8}`,
		"tick with null at":                     `{"kind":"tick","version":1,"sequence":8,"at":null}`,
		"accept-error error empty":              `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"","backoff_ms":5}`,
		"accept-error error null":               `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":null,"backoff_ms":5}`,
		"accept-error pem in error":             `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"-----BEGIN X","backoff_ms":5}`,
		"accept-error backoff negative":         `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"e","backoff_ms":-1}`,
		"accept-error backoff as string":        `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"e","backoff_ms":"5"}`,
		"accept-error backoff as float":         `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"e","backoff_ms":5.0}`,
		"accept-error missing backoff":          `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"e"}`,
		"accept-error with an accept key":       `{"kind":"accept-error","version":1,"sequence":9,"at":"2026-09-24T11:02:06Z","error":"e","backoff_ms":5,"conn":1}`,
		"accept body under accept-error marker": `{"kind":"accept-error","version":1,"sequence":2,"at":"2026-09-24T11:00:01Z","conn":1,"listener":"127.0.0.1:8443","remote":"10.0.0.7:51000"}`,
		"refusal source outside set":            `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","source":"emitter","error":"x"}`,
		"refusal source null":                   `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","source":null,"error":"x"}`,
		"refusal error empty":                   `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","source":"status-listener","error":""}`,
		"refusal error null":                    `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","source":"status-listener","error":null}`,
		"refusal missing error":                 `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","source":"status-listener"}`,
		"refusal with a backoff key":            `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","source":"status-listener","error":"x","backoff_ms":5}`,
		"reload body under refusal marker":      `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","outcome":"failed","error":"x","serving":false,"material":[]}`,
		"not an object after the marker":        `{"kind":"acl",`,
		"invalid utf-8":                         "{\"kind\":\"acl\",\"version\":1,\"sequence\":4,\"at\":\"2026-09-24T11:00:01Z\",\"conn\":1,\"decision\":\"allow\",\"rule\":\"r\",\"reason\":\"\xff\"}",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := gtDecodeLine([]byte(line)); err == nil {
				t.Fatalf("decoded: %s", line)
			}
		})
	}
	// And the healthy lines all decode, so the rejections above are not
	// the decoder rejecting everything.
	for i, line := range gtLines {
		if _, err := gtDecodeLine([]byte(line)); err != nil {
			t.Fatalf("healthy line %d: %v", i+1, err)
		}
	}
	// Whitespace after the marker is any valid JSON and is accepted.
	if _, err := gtDecodeLine([]byte(`{"kind":"acl", "version" : 1, "sequence":4,"at":"2026-09-24T11:00:01Z","conn":1,"decision":"allow","rule":"r","reason":""}`)); err != nil {
		t.Fatalf("whitespace within the remainder: %v", err)
	}
}

// TestGTDecodeSandbox pins the two sandbox keys of the start line (README
// 1.2): the closed state set, the acceptance null or a non-empty string,
// and the cross-field rule that ghostunnel never writes an acceptance
// beside any state but unsupported, which the reader holds it to.
func TestGTDecodeSandbox(t *testing.T) {
	line := func(state, accepted string) string {
		return `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":` + state + `,"sandbox_accepted":` + accepted + `,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`
	}
	for _, state := range []string{"applied", "unsupported", "disabled", "failed", "skipped"} {
		rec, err := gtDecodeLine([]byte(line(`"`+state+`"`, "null")))
		if err != nil {
			t.Fatalf("state %s with no acceptance: %v", state, err)
		}
		if rec.Start.Config.SandboxState != state || rec.Start.Config.SandboxAccepted != nil {
			t.Fatalf("state %s decoded as %+v", state, rec.Start.Config)
		}
		_, err = gtDecodeLine([]byte(line(`"`+state+`"`, `"windows"`)))
		if state == "unsupported" && err != nil {
			t.Fatalf("unsupported with an acceptance: %v", err)
		}
		if state != "unsupported" && err == nil {
			t.Fatalf("state %s with an acceptance decoded", state)
		}
	}
	rec, err := gtDecodeLine([]byte(line(`"unsupported"`, `"windows"`)))
	if err != nil || rec.Start.Config.SandboxAccepted == nil || *rec.Start.Config.SandboxAccepted != "windows" {
		t.Fatalf("acceptance decoded wrongly: %v %+v", err, rec.Start)
	}
	// The key set is exactly the README's, in its order, and landlock is
	// not in it.
	want := []string{"mode", "listen", "target", "proxy_protocol", "status_listen", "status_client_cert", "pprof_cmdline_redacted", "shutdown_requires_client_cert", "session_tickets", "verify_on_resume", "acl", "lifetime_cap_seconds", "sandbox_state", "sandbox_accepted", "material", "binary"}
	if strings.Join(gtConfigKeys, ",") != strings.Join(want, ",") {
		t.Fatalf("config keys %v, want %v", gtConfigKeys, want)
	}
}

// TestGTDecodeProxyProtocol pins the start line's proxy_protocol (README
// 1.2): what the backend is handed ahead of each connection, from a
// closed set, required. A line without the key is malformed, not a mode
// of off: a proxy that does not say what it hands the backend cannot be
// compared with what the operator expects.
func TestGTDecodeProxyProtocol(t *testing.T) {
	line := func(pp string) string {
		return `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t",` + pp + `"status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`
	}
	for _, pp := range []string{"off", "conn", "tls", "tls-full"} {
		rec, err := gtDecodeLine([]byte(line(`"proxy_protocol":"` + pp + `",`)))
		if err != nil {
			t.Fatalf("%s: %v", pp, err)
		}
		if rec.Start.Config.ProxyProtocol != pp {
			t.Fatalf("%s decoded as %q", pp, rec.Start.Config.ProxyProtocol)
		}
	}
	for name, pp := range map[string]string{
		"absent": ``, "empty": `"proxy_protocol":"",`, "null": `"proxy_protocol":null,`, "boolean": `"proxy_protocol":false,`,
		"outside the set": `"proxy_protocol":"v2",`, "upper-case": `"proxy_protocol":"TLS-FULL",`, "misplaced": `"proxy_protocol":"off","proxy_protocol":"off",`,
	} {
		if _, err := gtDecodeLine([]byte(line(pp))); err == nil {
			t.Errorf("proxy_protocol %s decoded", name)
		}
	}
	if strings.Join(gtProxyProtocols, ",") != "off,conn,tls,tls-full" {
		t.Fatalf("proxy protocol set %v is not the README's", gtProxyProtocols)
	}
}

// TestGTDecodeBinary pins the start line's binary (README 1.2): the
// executable the process started from, as exactly a non-empty path and a
// lower-case SHA-256, required. A line without it is malformed: a proxy
// that does not say which file it runs cannot be held to the operator's
// expectation of it.
func TestGTDecodeBinary(t *testing.T) {
	hash := strings.Repeat("c", 64)
	line := func(binary string) string {
		return `{"kind":"start","version":1,"sequence":1,"at":"2026-09-24T11:00:00Z","boot":1,"pid":4242,"config":{"mode":"server","listen":"l","target":"t","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":300,"sandbox_state":"applied","sandbox_accepted":null,"material":[]` + binary + `}}`
	}
	rec, err := gtDecodeLine([]byte(line(`,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + hash + `"}`)))
	if err != nil {
		t.Fatalf("control line: %v", err)
	}
	if got := rec.Start.Config.Binary; got != (gtBinary{Path: "/usr/local/bin/ghostunnel", SHA256: hash}) {
		t.Fatalf("binary decoded as %+v", got)
	}
	for name, binary := range map[string]string{
		"absent":        ``,
		"null":          `,"binary":null`,
		"string":        `,"binary":"/usr/local/bin/ghostunnel"`,
		"array":         `,"binary":[]`,
		"no path":       `,"binary":{"sha256":"` + hash + `"}`,
		"no hash":       `,"binary":{"path":"/usr/local/bin/ghostunnel"}`,
		"unknown key":   `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + hash + `","size":1}`,
		"duplicate key": `,"binary":{"path":"/a","path":"/b","sha256":"` + hash + `"}`,
		"empty path":    `,"binary":{"path":"","sha256":"` + hash + `"}`,
		"null path":     `,"binary":{"path":null,"sha256":"` + hash + `"}`,
		"pem in path":   `,"binary":{"path":"-----BEGIN X-----","sha256":"` + hash + `"}`,
		"null hash":     `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":null}`,
		"short hash":    `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + hash[:63] + `"}`,
		"upper hash":    `,"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"` + strings.ToUpper(hash) + `"}`,
	} {
		if _, err := gtDecodeLine([]byte(line(binary))); err == nil {
			t.Errorf("binary %s decoded", name)
		}
	}
	if strings.Join(gtBinaryKeys, ",") != "path,sha256" {
		t.Fatalf("binary keys %v are not the README's", gtBinaryKeys)
	}
}

// ---- the decode memory: a resumed decode is a full decode ----------------

// gtSynthLines makes n lines of one healthy boot ending at end: the start
// line, connections of four lines each (accept, handshake, acl, close), a
// tick every so often, and a tick at end as the last line. Timestamps
// advance one second per hundred lines, so they never go back and every
// connection closes within the lifetime cap. The lines before the final
// tick end on a closed connection or a tick, so the boot leaves nothing
// open for lifetime-cap or acl-before-serve to wait on.
func gtSynthLines(n int, end time.Time) []string {
	if n < 2 {
		n = 2
	}
	t0 := end.Add(-time.Duration(n/100+2) * time.Second)
	at := func(i int) string {
		return t0.Add(time.Duration(i/100) * time.Second).UTC().Format(gtTimestampLayout)
	}
	tick := func(seq int, when string) string {
		return fmt.Sprintf(`{"kind":"tick","version":1,"sequence":%d,"at":"%s"}`, seq, when)
	}
	lines := make([]string, 0, n)
	lines = append(lines, strings.Replace(gtLines[0], `"at":"2026-09-24T11:00:00Z"`, `"at":"`+at(0)+`"`, 1))
	conn := int64(0)
	phase := 0 // 0 accept, 1 handshake, 2 acl, 3 close
	for len(lines) < n-1 {
		seq := len(lines) + 1
		if phase == 0 && seq%41 == 0 {
			lines = append(lines, tick(seq, at(seq)))
			continue
		}
		if phase == 0 && len(lines)+4 > n-1 {
			// No room for a whole connection: ticks to the end.
			lines = append(lines, tick(seq, at(seq)))
			continue
		}
		switch phase {
		case 0:
			conn++
			lines = append(lines, fmt.Sprintf(`{"kind":"accept","version":1,"sequence":%d,"at":"%s","conn":%d,"listener":"127.0.0.1:8443","remote":"10.0.0.7:51000"}`, seq, at(seq), conn))
		case 1:
			// Every connection presented the test PKI's allowed chain,
			// which the start line's CA verifies and its rule allows
			// (substance.go); the root the lines are written under
			// carries the chain (gtInstallChains).
			lines = append(lines, fmt.Sprintf(`{"kind":"handshake","version":1,"sequence":%d,"at":"%s","conn":%d,"outcome":"ok","resumed":false,"verified":true,"protocol":"TLS1.3","peer":{"subject":"CN=client","issuer":"CN=ca","serial":"0a","sans":["dns:client.example"],"fingerprint":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"error":null,"chain":"%s"}`, seq, at(seq), conn, gtChainClient))
		case 2:
			lines = append(lines, fmt.Sprintf(`{"kind":"acl","version":1,"sequence":%d,"at":"%s","conn":%d,"decision":"allow","rule":"allow-cn","reason":"cn matched"}`, seq, at(seq), conn))
		case 3:
			lines = append(lines, fmt.Sprintf(`{"kind":"close","version":1,"sequence":%d,"at":"%s","conn":%d,"reason":"eof","duration_ms":0}`, seq, at(seq), conn))
		}
		phase = (phase + 1) % 4
	}
	lines = append(lines, tick(len(lines)+1, end.UTC().Format(gtTimestampLayout)))
	return lines
}

// gtCountDecodes counts the lines gtReadBoot decodes for the rest of the
// test.
func gtCountDecodes(t *testing.T) *int {
	t.Helper()
	prev := gtDecode
	n := 0
	gtDecode = func(line []byte) (gtRecord, error) {
		n++
		return prev(line)
	}
	t.Cleanup(func() { gtDecode = prev })
	return &n
}

// gtSameRead reads root twice, without a memory and with mem, and fails
// unless the two agree: the same error, or the same boot number, torn
// flag, segments (name, prefix and the sum of the whole prefix) and
// records. It returns the read with the memory.
func gtSameRead(t *testing.T, root string, mem *gtDecodeMemory) (*gtBoot, error) {
	t.Helper()
	full, ferr := gtReadLatest(root)
	got, gerr := gtReadLatestFrom(root, gtListRoot(root), mem)
	if (ferr == nil) != (gerr == nil) || (ferr != nil && ferr.Error() != gerr.Error()) {
		t.Fatalf("read with memory: %v; without: %v", gerr, ferr)
	}
	if ferr != nil {
		if len(mem.Segments) != 0 {
			t.Fatalf("a failed read left %d segments in memory", len(mem.Segments))
		}
		return got, gerr
	}
	if got.Number != full.Number || got.Torn != full.Torn {
		t.Fatalf("with memory: boot %d torn %v; without: boot %d torn %v", got.Number, got.Torn, full.Number, full.Torn)
	}
	if !reflect.DeepEqual(got.Records, full.Records) {
		t.Fatalf("records differ: with memory %d, without %d", len(got.Records), len(full.Records))
	}
	if len(got.Segments) != len(full.Segments) {
		t.Fatalf("segments: with memory %d, without %d", len(got.Segments), len(full.Segments))
	}
	for i := range got.Segments {
		g, f := got.Segments[i], full.Segments[i]
		if g.Name != f.Name || !bytes.Equal(g.Prefix, f.Prefix) || g.Sums[int64(len(g.Prefix))] != f.Sums[int64(len(f.Prefix))] {
			t.Fatalf("segment %d differs: %s/%d vs %s/%d", i, g.Name, len(g.Prefix), f.Name, len(f.Prefix))
		}
	}
	return got, nil
}

// Every state a growing, torn, rewritten, shrunk, broken, mended and
// replaced boot goes through reads the same with the memory as without.
func TestGTDecodeMemoryMatchesFullDecode(t *testing.T) {
	root := t.TempDir()
	mem := &gtDecodeMemory{}
	seg := func(boot, name string, data []byte) { gtWriteSegment(t, root, boot, name, data) }

	seg("0000000001", "0000000001.trace", gtJoin(gtLines[:3]...))
	gtSameRead(t, root, mem)
	if m := mem.Segments["0000000001.trace"]; mem.Boot != 1 || m == nil || m.Length != int64(len(gtJoin(gtLines[:3]...))) || len(m.Records) != 3 || m.Next != 4 {
		t.Fatalf("memory after the first read: %+v", mem)
	}
	// Grown, with a torn tail.
	seg("0000000001", "0000000001.trace", append(gtJoin(gtLines[:5]...), []byte(`{"kind":"reload","version":1,"sequ`)...))
	gtSameRead(t, root, mem)
	// The torn line completed, and a second segment.
	seg("0000000001", "0000000001.trace", gtJoin(gtLines[:6]...))
	seg("0000000001", "0000000007.trace", gtJoin(gtLines[6:]...))
	b, _ := gtSameRead(t, root, mem)
	if len(b.Records) != len(gtLines) || len(mem.Segments) != 2 {
		t.Fatalf("after the second segment: %d records, %d segments in memory", len(b.Records), len(mem.Segments))
	}
	// One past line rewritten in place, same length: the records say so.
	lines := append([]string{}, gtLines...)
	lines[2] = replaceOnce(t, lines[2], `"serial":"0a"`, `"serial":"0b"`)
	seg("0000000001", "0000000001.trace", padTo(t, gtJoin(lines[:6]...), len(gtJoin(gtLines[:6]...))))
	b, _ = gtSameRead(t, root, mem)
	if b.Records[2].Handshake.Peer.Serial != "0b" {
		t.Fatalf("the rewritten line was not decoded: serial %q", b.Records[2].Handshake.Peer.Serial)
	}
	// The first segment's last timestamp moved on past the second's first:
	// rule 10 across the segment boundary, from a remembered state.
	lines[5] = replaceOnce(t, lines[5], `"at":"2026-09-24T11:01:00Z"`, `"at":"2026-09-24T11:03:00Z"`)
	seg("0000000001", "0000000001.trace", padTo(t, gtJoin(lines[:6]...), len(gtJoin(gtLines[:6]...))))
	if _, err := gtSameRead(t, root, mem); err == nil || gtSubject(err) != "0000000001/0000000007.trace:1" {
		t.Fatalf("timestamp back across segments: %v", err)
	}
	// Mended, then shrunk below the second segment's name (rule 4).
	seg("0000000001", "0000000001.trace", gtJoin(gtLines[:6]...))
	gtSameRead(t, root, mem)
	seg("0000000001", "0000000001.trace", gtJoin(gtLines[:2]...))
	if _, err := gtSameRead(t, root, mem); err == nil {
		t.Fatal("a shrunk first segment read")
	}
	// The second segment gone, the first at four lines: read afresh.
	if err := os.Remove(filepath.Join(root, "0000000001", "0000000007.trace")); err != nil {
		t.Fatal(err)
	}
	seg("0000000001", "0000000001.trace", gtJoin(gtLines[:4]...))
	gtSameRead(t, root, mem)
	// A malformed line appended: the same error, and nothing remembered.
	seg("0000000001", "0000000001.trace", append(gtJoin(gtLines[:4]...), []byte("{\"kind\":\"tick\",\"version\":1,\"sequence\":5,\"at\":\"soon\"}\n")...))
	if _, err := gtSameRead(t, root, mem); err == nil || gtSubject(err) != "0000000001/0000000001.trace:5" {
		t.Fatalf("malformed line: %v", err)
	}
	// Mended with every line; then a new boot.
	seg("0000000001", "0000000001.trace", gtJoin(gtLines...))
	gtSameRead(t, root, mem)
	seg("0000000002", "0000000001.trace", gtJoin(replaceOnce(t, gtLines[0], `"boot":1`, `"boot":2`)))
	b, _ = gtSameRead(t, root, mem)
	if b.Number != 2 || mem.Boot != 2 || len(mem.Segments) != 1 {
		t.Fatalf("after a new boot: %d, memory %+v", b.Number, mem)
	}
	// The boot directory gone: the same error.
	if err := os.RemoveAll(filepath.Join(root, "0000000002")); err != nil {
		t.Fatal(err)
	}
	seg("0000000001", "0000000001.trace", gtJoin(gtLines...))
	gtSameRead(t, root, mem)
}

// The memory spares the decode of every line whose bytes are unchanged: a
// second read of a grown boot decodes the new lines and no other, and
// returns what a full decode returns.
func TestGTDecodeMemoryDecodesOnlyNewLines(t *testing.T) {
	root := t.TempDir()
	end := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	lines := gtSynthLines(400, end)
	mem := &gtDecodeMemory{}
	n := gtCountDecodes(t)
	// read reads with the memory, counting only that read's decodes, and
	// checks it against a full decode.
	read := func(want int) {
		t.Helper()
		full, err := gtReadLatest(root)
		if err != nil {
			t.Fatal(err)
		}
		*n = 0
		got, err := gtReadLatestFrom(root, gtListRoot(root), mem)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Records, full.Records) {
			t.Fatalf("records differ from a full decode")
		}
		if *n != want {
			t.Fatalf("decoded %d lines, want %d", *n, want)
		}
	}
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines[:300]...))
	read(300)
	// Unchanged: nothing decoded.
	read(0)
	// Grown by 40 lines: those 40.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines[:340]...))
	read(40)
	// A byte changed in the remembered prefix: everything.
	changed := append([]string{}, lines[:340]...)
	changed[2] = replaceOnce(t, changed[2], `"serial":"0a"`, `"serial":"0b"`)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", padTo(t, gtJoin(changed...), len(gtJoin(lines[:340]...))))
	read(340)
}

// A line of the remembered prefix rewritten in place with the same length,
// changing what the surface checks find: the records the checks see are
// the disk's, in the cycle that reads it. A memory keyed by length alone
// would hand the checks the old line.
func TestGTDecodeMemoryRewrittenInPlaceIsSeen(t *testing.T) {
	root := t.TempDir()
	st := &State{}
	now := time.Date(2026, 9, 24, 11, 3, 0, 0, time.UTC)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	boot, _, err := traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	if f := tunnelSurfaceFindings(boot, now, 0, 0, 0); len(f) != 0 {
		t.Fatalf("healthy boot: %v", f)
	}
	traceConsistentFindings(st, boot)
	// The handshake now names connection 9, which nothing accepted.
	lines := append([]string{}, gtLines...)
	lines[2] = replaceOnce(t, lines[2], `"conn":1,`, `"conn":9,`)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", padTo(t, gtJoin(lines...), len(gtJoin(gtLines...))))
	boot, _, err = traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	if boot.Records[2].Handshake.Conn != 9 {
		t.Fatalf("the rewritten line was not decoded: conn %d", boot.Records[2].Handshake.Conn)
	}
	want := Finding{Check: checkConnConsistent, Subject: "9"}
	found := false
	for _, f := range tunnelSurfaceFindings(boot, now, 0, 0, 0) {
		if f == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("the surface did not see the rewritten line")
	}
	tmWant(t, traceConsistentFindings(st, boot), Finding{Check: checkTraceConsistent, Subject: "0000000001/0000000001.trace"})
}

// gtSums is one pass with a sum at each length: each sum is the SHA-256 of
// exactly that prefix.
func TestGTSumsAreTheHashesOfEachPrefix(t *testing.T) {
	b := gtJoin(gtLines...)
	at := []int64{0, 1, 17, int64(len(b)) / 2, int64(len(b)) - 1, int64(len(b))}
	sums := gtSums(b, at...)
	if len(sums) != len(at) {
		t.Fatalf("%d sums for %d lengths", len(sums), len(at))
	}
	for _, n := range at {
		want := sha256.Sum256(b[:n])
		if sums[n] != hex.EncodeToString(want[:]) {
			t.Errorf("sum at %d differs from the hash of the prefix", n)
		}
	}
	// Out-of-range lengths are ignored; the whole prefix is always summed.
	if s := gtSums(b, -1, int64(len(b))+1); len(s) != 1 || s[int64(len(b))] != sums[int64(len(b))] {
		t.Errorf("out-of-range lengths: %v", s)
	}
}

// ---- the segment rule: a pre-extended segment reads as its content ------

// gtNULs is n NUL bytes: the unwritten space of a pre-extended segment.
func gtNULs(n int) []byte { return make([]byte, n) }

// gtPreExtended is content followed by NUL bytes up to size, the shape of
// the live segment, or of the last segment of a boot that crashed.
func gtPreExtended(t *testing.T, content []byte, size int) []byte {
	t.Helper()
	if len(content) > size {
		t.Fatalf("content of %d bytes does not fit a segment of %d", len(content), size)
	}
	return append(append([]byte{}, content...), gtNULs(size-len(content))...)
}

// A segment whose content is followed by NUL bytes reads as its content:
// the same records, not torn, and the prefix the memory and trace-consistent
// see is the content's, never the file's.
func TestGTPreExtendedSegmentReadsAsContent(t *testing.T) {
	root := t.TempDir()
	content := gtJoin(gtLines...)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtPreExtended(t, content, 4096))
	b, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Torn || len(b.Records) != len(gtLines) {
		t.Fatalf("torn=%v records=%d, want not torn and %d", b.Torn, len(b.Records), len(gtLines))
	}
	if len(b.Segments) != 1 || !bytes.Equal(b.Segments[0].Prefix, content) {
		t.Fatalf("prefix is %d bytes, want the %d bytes of content", len(b.Segments[0].Prefix), len(content))
	}
	exact := gtOneBoot(t, gtLines...)
	e, err := gtReadLatest(exact)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.Records, e.Records) || b.Segments[0].Sums[int64(len(content))] != e.Segments[0].Sums[int64(len(content))] {
		t.Fatal("the pre-extended segment and the exact segment read differently")
	}
}

// A partial line followed by NUL bytes is a torn tail of the content: the
// complete lines are the records, Torn is reported, and the prefix ends at
// the last line feed as it does for an exact segment.
func TestGTPreExtendedSegmentTornTail(t *testing.T) {
	root := t.TempDir()
	whole := gtJoin(gtLines[:5]...)
	content := append(append([]byte{}, whole...), []byte(`{"kind":"reload","version":1,"sequ`)...)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtPreExtended(t, content, 4096))
	b, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Torn || len(b.Records) != 5 {
		t.Fatalf("torn=%v records=%d, want torn and 5", b.Torn, len(b.Records))
	}
	if !bytes.Equal(b.Segments[0].Prefix, whole) {
		t.Fatalf("prefix is %d bytes, want %d", len(b.Segments[0].Prefix), len(whole))
	}
	// The same torn tail in a segment that is not the last is still rule 5.
	gtWriteSegment(t, root, "0000000001", "0000000006.trace", gtPreExtended(t, gtJoin(gtLines[5:]...), 4096))
	_, err = gtReadLatest(root)
	if err == nil || gtSubject(err) != "0000000001/0000000001.trace:6" {
		t.Fatalf("torn tail in a segment that is not the last: %v", err)
	}
}

// A segment of NUL bytes alone has no content: as the last segment named by
// the next sequence it is the empty last segment of rule 6, benign; as the
// only segment it is a boot with no line yet.
func TestGTPreExtendedSegmentWithNoContentIsEmpty(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtNULs(4096))
	b, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Records) != 0 || b.Torn || len(b.Segments) != 1 || len(b.Segments[0].Prefix) != 0 {
		t.Fatalf("a NUL-only segment read as records=%d torn=%v", len(b.Records), b.Torn)
	}
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	gtWriteSegment(t, root, "0000000001", "0000000010.trace", gtNULs(4096))
	b, err = gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Records) != len(gtLines) || b.Torn {
		t.Fatalf("a NUL-only last segment after a whole one: records=%d torn=%v", len(b.Records), b.Torn)
	}
}

// Content longer than one chunk is read whole, chunk after chunk, and the
// read stops in the chunk holding the first NUL: what a file of 64 MiB with
// a few MiB of content costs is the content plus one chunk, and what it
// yields is the exact content.
func TestGTPreExtendedSegmentContentSpansChunks(t *testing.T) {
	root := t.TempDir()
	end := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	lines := gtSynthLines(12000, end)
	content := gtJoin(lines...)
	if len(content) <= gtReadChunkBytes {
		t.Fatalf("test content is %d bytes, not more than one chunk of %d", len(content), gtReadChunkBytes)
	}
	size := 3 * gtReadChunkBytes
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtPreExtended(t, content, size))
	data, err := gtReadSegment(filepath.Join(root, "0000000001", "0000000001.trace"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("content read is %d bytes, want %d", len(data), len(content))
	}
	b, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Torn || len(b.Records) != len(lines) {
		t.Fatalf("torn=%v records=%d, want not torn and %d", b.Torn, len(b.Records), len(lines))
	}
	// A NUL exactly on a chunk boundary: the content is the first chunk.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtPreExtended(t, content[:gtReadChunkBytes], size))
	data, err = gtReadSegment(filepath.Join(root, "0000000001", "0000000001.trace"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != gtReadChunkBytes {
		t.Fatalf("content read is %d bytes, want exactly one chunk", len(data))
	}
}

// The normal case now: the file's size is constant while its content
// grows. The decode memory resumes and trace-consistent sees a segment
// that only grew; a byte of the content rewritten under the same size is
// still seen, since every length is a length of content.
func TestGTPreExtendedSegmentGrowsUnderConstantSize(t *testing.T) {
	root := t.TempDir()
	st := &State{}
	const size = 8192
	name := "0000000001.trace"
	gtWriteSegment(t, root, "0000000001", name, gtPreExtended(t, gtJoin(gtLines[:3]...), size))
	boot, _, err := traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(boot.Records) != 3 {
		t.Fatalf("records %d, want 3", len(boot.Records))
	}
	tmWant(t, traceConsistentFindings(st, boot))
	if m := st.TraceSegments[name]; m.Length != int64(len(gtJoin(gtLines[:3]...))) {
		t.Fatalf("trace-consistent remembered %d bytes, want the content's %d", m.Length, len(gtJoin(gtLines[:3]...)))
	}
	// Grown within the same file size: only the new lines are decoded.
	decodes := gtCountDecodes(t)
	gtWriteSegment(t, root, "0000000001", name, gtPreExtended(t, gtJoin(gtLines...), size))
	boot, _, err = traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(boot.Records) != len(gtLines) || boot.Torn {
		t.Fatalf("records %d torn=%v, want %d and not torn", len(boot.Records), boot.Torn, len(gtLines))
	}
	if *decodes != len(gtLines)-3 {
		t.Fatalf("decoded %d lines, want the %d new ones", *decodes, len(gtLines)-3)
	}
	tmWant(t, traceConsistentFindings(st, boot))
	if m := st.TraceSegments[name]; m.Length != int64(len(gtJoin(gtLines...))) {
		t.Fatalf("trace-consistent remembered %d bytes, want the content's %d", m.Length, len(gtJoin(gtLines...)))
	}
	// Closed exact: the emitter truncated the file to its content. The
	// same content, the same conclusion.
	gtWriteSegment(t, root, "0000000001", name, gtJoin(gtLines...))
	boot, _, err = traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	tmWant(t, traceConsistentFindings(st, boot))
	// Rewritten under a constant size: seen.
	lines := append([]string{}, gtLines...)
	lines[2] = replaceOnce(t, lines[2], `"conn":1,`, `"conn":9,`)
	gtWriteSegment(t, root, "0000000001", name, gtPreExtended(t, gtJoin(lines...), size))
	boot, _, err = traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	tmWant(t, traceConsistentFindings(st, boot), Finding{Check: checkTraceConsistent, Subject: "0000000001/" + name})
	// Shrunk in content under a constant size: seen.
	gtWriteSegment(t, root, "0000000001", name, gtPreExtended(t, gtJoin(gtLines[:3]...), size))
	boot, _, err = traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	tmWant(t, traceConsistentFindings(st, boot), Finding{Check: checkTraceConsistent, Subject: "0000000001/" + name})
}

// ---- the cost: the read with and without the memory ---------------------

// gtBenchBoot writes one boot of n lines under a fresh root, ending at end,
// and returns the root.
func gtBenchBoot(b *testing.B, n int, end time.Time) string {
	b.Helper()
	root := b.TempDir()
	dir := filepath.Join(root, "0000000001")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0000000001.trace"), gtJoin(gtSynthLines(n, end)...), 0o644); err != nil {
		b.Fatal(err)
	}
	return root
}

// BenchmarkGTRead is the read of the current boot at three sizes, every
// line decoded (full) and resumed from the memory of the previous read
// (memory), the boot unchanged between reads as it is between two cycles
// with no new connection.
func BenchmarkGTRead(b *testing.B) {
	end := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	for _, n := range []int{300, 10000, 100000} {
		root := gtBenchBoot(b, n, end)
		b.Run(fmt.Sprintf("full/%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := gtReadLatest(root); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("memory/%d", n), func(b *testing.B) {
			mem := &gtDecodeMemory{}
			if _, err := gtReadLatestFrom(root, gtListRoot(root), mem); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := gtReadLatestFrom(root, gtListRoot(root), mem); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// gtRefusalLine is the one refusal line a boot may carry (README 1.2): the
// status listener died and the proxy refuses to serve until restart. It is
// not among gtLines, whose boot is the healthy one every surface test
// judges clean.
const gtRefusalLine = `{"kind":"refusal","version":1,"sequence":10,"at":"2026-09-24T11:02:07Z","source":"status-listener","error":"accept tcp 127.0.0.1:6060: use of closed network connection"}`

// TestGTDecodeRefusal: the refusal kind classifies by its marker, decodes
// to its two fields and nothing else, and reads in a boot after the
// healthy lines.
func TestGTDecodeRefusal(t *testing.T) {
	if got := gtClassify([]byte(gtRefusalLine)); got != "refusal" {
		t.Fatalf("classified as %q", got)
	}
	rec, err := gtDecodeLine([]byte(gtRefusalLine))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != "refusal" || rec.Sequence != 10 || rec.Refusal == nil || rec.Refusal.Source != "status-listener" || rec.Refusal.Error != "accept tcp 127.0.0.1:6060: use of closed network connection" || rec.AcceptError != nil || rec.Reload != nil {
		t.Fatalf("refusal decoded wrongly: %+v", rec)
	}
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(append(append([]string{}, gtLines...), gtRefusalLine)...))
	b, err := gtReadLatest(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Records) != 10 || b.Records[9].Kind != "refusal" || b.Records[9].Refusal == nil {
		t.Fatalf("boot with a refusal line read wrongly: %d records", len(b.Records))
	}
}

// TestGTReadSegmentBoundsContent: a segment's content is read up to the
// emitter's own segment size and no further. Exactly that many bytes with
// no NUL read whole; one byte more is refused, not held in memory.
func TestGTReadSegmentBoundsContent(t *testing.T) {
	root := t.TempDir()
	full := bytes.Repeat([]byte{'x'}, gtMaxSegmentBytes)
	p := filepath.Join(root, "full.trace")
	if err := os.WriteFile(p, full, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := gtReadSegment(p)
	if err != nil || len(got) != gtMaxSegmentBytes {
		t.Fatalf("content of exactly the bound: %d bytes, %v", len(got), err)
	}
	over := filepath.Join(root, "over.trace")
	if err := os.WriteFile(over, append(full, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := gtReadSegment(over); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("content past the bound read: %v", err)
	}
}
