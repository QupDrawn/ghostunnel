package main

// localchecks_test.go proves the tunnel member's surface checks against
// synthetic gt/ trees written by hand in the exact ringtrace format: one
// healthy tree that yields nothing, one tree per violation that yields
// exactly the expected finding, and the unreadable trees that must yield a
// finding for every check because no check could run.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const tunnelNow = "2026-09-24T12:00:00Z"

// tunnelConfig is a healthy start-line config: a lifetime cap of 300 s,
// tickets on with verification re-run on resumption, and the test PKI's
// CA bundle as the trust material the substance rules verify chains
// against (gtreader_test.go, gtPKI).
const tunnelConfig = `{"mode":"server","listen":"localhost:8443","target":"localhost:8080","proxy_protocol":"off","status_listen":"127.0.0.1:6060","status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":true,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":300,"sandbox_state":"applied","sandbox_accepted":null,"material":[{"material":"ca","path":"../testdata/pki/ca.pem","sha256":"` + gtCAHash + `"}],"binary":{"path":"/usr/local/bin/ghostunnel","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`

func tHdr(kind string, seq int, at string) string {
	return fmt.Sprintf(`{"kind":"%s","version":1,"sequence":%d,"at":"%s"`, kind, seq, at)
}

func tStart(seq int, at string, boot int, config string) string {
	return fmt.Sprintf(`%s,"boot":%d,"pid":4242,"config":%s}`, tHdr("start", seq, at), boot, config)
}

func tAccept(seq int, at string, conn int) string {
	return fmt.Sprintf(`%s,"conn":%d,"listener":"127.0.0.1:8443","remote":"10.0.0.7:5%04d"}`, tHdr("accept", seq, at), conn, conn)
}

// tHandshake is a handshake that presented the test PKI's allowed chain
// (CN client.example, the one the config's rule allows); tHandshakeChain
// names another, or none.
func tHandshake(seq int, at string, conn int, outcome string, resumed, verified bool) string {
	return tHandshakeChain(seq, at, conn, outcome, resumed, verified, gtChainClient)
}

func tHandshakeChain(seq int, at string, conn int, outcome string, resumed, verified bool, chain string) string {
	line := fmt.Sprintf(`%s,"conn":%d,"outcome":"%s","resumed":%t,"verified":%t,"protocol":"TLS1.3","peer":null,"error":null`, tHdr("handshake", seq, at), conn, outcome, resumed, verified)
	if chain != "" {
		line += `,"chain":"` + chain + `"`
	}
	return line + "}"
}

func tACL(seq int, at string, conn int, decision string) string {
	return fmt.Sprintf(`%s,"conn":%d,"decision":"%s","rule":"allow-cn","reason":"cn"}`, tHdr("acl", seq, at), conn, decision)
}

func tClose(seq int, at string, conn int, reason string, ms int) string {
	return fmt.Sprintf(`%s,"conn":%d,"reason":"%s","duration_ms":%d}`, tHdr("close", seq, at), conn, reason, ms)
}

func tTick(seq int, at string) string {
	return tHdr("tick", seq, at) + "}"
}

func tAcceptError(seq int, at string, err string, backoff int) string {
	return fmt.Sprintf(`%s,"error":%q,"backoff_ms":%d}`, tHdr("accept-error", seq, at), err, backoff)
}

// tunnelRun runs TunnelChecks over a tree and returns its findings sorted.
func tunnelRun(t *testing.T, root string, checks TunnelChecks) []Finding {
	t.Helper()
	now, err := time.Parse(time.RFC3339, tunnelNow)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{TracesRoot: root, Now: now}
	if checks.Live == nil {
		// Nobody is live in an empty process table: the trees here name
		// pid 4242, which may or may not be a process on this host, so
		// the table holds it: the highest boot's process must read live.
		checks.Live = procLiveness(blTable(t, 4242))
	}
	got := checks.Run(cfg, &State{}, nil)
	sort.Slice(got, func(i, j int) bool {
		if got[i].Check != got[j].Check {
			return got[i].Check < got[j].Check
		}
		return got[i].Subject < got[j].Subject
	})
	// Every finding must be one the member declares (SPEC 15).
	ids := map[string]bool{}
	for _, id := range checks.Identifiers() {
		ids[id] = true
	}
	for _, f := range got {
		if !ids[f.Check] {
			t.Fatalf("finding %v names an undeclared identifier", f)
		}
	}
	return got
}

func tunnelWant(t *testing.T, got []Finding, want ...Finding) {
	t.Helper()
	sort.Slice(want, func(i, j int) bool {
		if want[i].Check != want[j].Check {
			return want[i].Check < want[j].Check
		}
		return want[i].Subject < want[j].Subject
	})
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings\n got %v\nwant %v", got, want)
	}
}

// tunnelHealthy is a boot with every shape of connection the checks accept:
// a full verified handshake served and closed inside the cap; a resumed and
// re-verified session; a denied connection closed as refused; a refused
// handshake; a connection the gate halted before any handshake; a served
// connection still open inside the cap; an accepted connection whose
// handshake has just finished and whose acl line is still to come; and a
// tick one second before now. The denied connection presented the chain
// the rule does not allow (CN other.example), so its denial is one the
// substance rules agree with; every other chain is the allowed one.
func tunnelHealthy() []string {
	return []string{
		tStart(1, "2026-09-24T11:00:00Z", 1, tunnelConfig),
		tAccept(2, "2026-09-24T11:00:01Z", 1),
		tHandshake(3, "2026-09-24T11:00:01Z", 1, "ok", false, true),
		tACL(4, "2026-09-24T11:00:01Z", 1, "allow"),
		tClose(5, "2026-09-24T11:00:09Z", 1, "eof", 8000),
		tAccept(6, "2026-09-24T11:00:10Z", 2),
		tHandshake(7, "2026-09-24T11:00:10Z", 2, "ok", true, true),
		tACL(8, "2026-09-24T11:00:10Z", 2, "allow"),
		tClose(9, "2026-09-24T11:05:10Z", 2, "lifetime", 300400),
		tAccept(10, "2026-09-24T11:10:00Z", 3),
		tACL(11, "2026-09-24T11:10:00Z", 3, "deny"),
		tHandshakeChain(12, "2026-09-24T11:10:00Z", 3, "ok", false, true, gtChainOther),
		tClose(13, "2026-09-24T11:10:00Z", 3, "refused", 3),
		tAccept(14, "2026-09-24T11:10:01Z", 4),
		tHandshake(15, "2026-09-24T11:10:01Z", 4, "refused", false, false),
		tClose(16, "2026-09-24T11:10:01Z", 4, "refused", 2),
		tAccept(17, "2026-09-24T11:10:02Z", 5),
		tClose(18, "2026-09-24T11:10:02Z", 5, "halt", 0),
		tAccept(19, "2026-09-24T11:58:00Z", 6),
		tHandshake(20, "2026-09-24T11:58:00Z", 6, "ok", false, true),
		tACL(21, "2026-09-24T11:58:00Z", 6, "allow"),
		tAccept(22, "2026-09-24T11:59:59Z", 7),
		tHandshake(23, "2026-09-24T11:59:59Z", 7, "ok", false, true),
		tTick(24, "2026-09-24T11:59:59Z"),
	}
}

// tRenumber rewrites each line's sequence to its position, so a test may
// drop or insert lines without opening a sequence gap.
func tRenumber(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		s := strings.Index(line, `"sequence":`) + len(`"sequence":`)
		e := s + strings.Index(line[s:], ",")
		out[i] = line[:s] + fmt.Sprint(i+1) + line[e:]
	}
	return out
}

// tReAt rewrites a line's timestamp.
func tReAt(line, at string) string {
	i := strings.Index(line, `"at":"`) + len(`"at":"`)
	return line[:i] + at + line[i+len(at):]
}

// tunnelTree writes one boot of the lines, renumbered, and returns the root.
func tunnelTree(t *testing.T, lines ...string) string {
	t.Helper()
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumber(lines)...))
	return root
}

func TestTunnelHealthyTreeYieldsNothing(t *testing.T) {
	root := tunnelTree(t, tunnelHealthy()...)
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{}))
	// With the expectations configured and met, still nothing.
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectListen: "localhost:8443", ExpectTarget: "localhost:8080", ExpectProxyProtocol: "off"}))
}

func TestTunnelIdentifiers(t *testing.T) {
	ids := TunnelChecks{}.Identifiers()
	// The surface's rules in evaluation order, the two substance rules
	// (substance.go) among them after accept-loop, the one expectation
	// that is never absent (proxy-protocol-expected: no expectation means
	// off), then the checks over the read itself.
	want := []string{"trace-readable", "conn-consistent", "handshake-verified", "resumption-verified", "acl-before-serve", "lifetime-cap", "accept-loop", "handshake-substance", "acl-substance", "proxy-protocol-expected", "tick-fresh", "trace-consistent", "boot-ambiguous", "boot-ended"}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Fatalf("identifiers %v, want %v", ids, want)
	}
	tail := []string{"proxy-protocol-expected", "tick-fresh", "trace-consistent", "boot-ambiguous", "boot-ended"}
	ids = TunnelChecks{ExpectListen: "localhost:8443"}.Identifiers()
	withListener := append(append(append([]string{}, want[:9]...), "listener-expected"), tail...)
	if fmt.Sprint(ids) != fmt.Sprint(withListener) {
		t.Fatalf("identifiers with a listener expectation %v, want %v", ids, withListener)
	}
	ids = TunnelChecks{ExpectTarget: "localhost:8080"}.Identifiers()
	withTarget := append(append(append([]string{}, want[:9]...), "target-expected"), tail...)
	if fmt.Sprint(ids) != fmt.Sprint(withTarget) {
		t.Fatalf("identifiers with a target expectation %v, want %v", ids, withTarget)
	}
	ids = TunnelChecks{ExpectACL: []string{"allow-all"}}.Identifiers()
	withACL := append(append(append([]string{}, want[:9]...), "acl-expected"), tail...)
	if fmt.Sprint(ids) != fmt.Sprint(withACL) {
		t.Fatalf("identifiers with an acl expectation %v, want %v", ids, withACL)
	}
	ids = TunnelChecks{ExpectListen: "localhost:8443", ExpectTarget: "localhost:8080", ExpectACL: []string{"allow-all"}, ExpectProxyProtocol: "tls"}.Identifiers()
	withAll := append(append(append([]string{}, want[:9]...), "listener-expected", "target-expected", "acl-expected"), tail...)
	if fmt.Sprint(ids) != fmt.Sprint(withAll) {
		t.Fatalf("identifiers with every expectation %v, want %v", ids, withAll)
	}
	// What this member judges of the other surfaces is listed once per
	// owner, and never among the local identifiers.
	ring := TunnelChecks{}.RingIdentifiers()
	if fmt.Sprint(ring) != fmt.Sprint([]string{"surface-disagree:admin", "surface-disagree:material"}) {
		t.Fatalf("ring identifiers %v", ring)
	}
}

func TestTunnelResumedUnverifiedIsAFinding(t *testing.T) {
	lines := tunnelHealthy()
	// Connection 2 resumed and was accepted without verification on this
	// handshake, although the config claims verification re-runs.
	lines[6] = tHandshake(7, "2026-09-24T11:00:10Z", 2, "ok", true, false)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"resumption-verified", "2"})
	// The same with the config saying resumption is not re-verified.
	lines[0] = tStart(1, "2026-09-24T11:00:00Z", 1, strings.Replace(tunnelConfig, `"verify_on_resume":true`, `"verify_on_resume":false`, 1))
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"resumption-verified", "2"})
}

func TestTunnelFullHandshakeUnverifiedIsAFinding(t *testing.T) {
	lines := tunnelHealthy()
	lines[2] = tHandshake(3, "2026-09-24T11:00:01Z", 1, "ok", false, false)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"handshake-verified", "1"})
}

func TestTunnelRefusedHandshakeNeedsNoVerification(t *testing.T) {
	lines := tunnelHealthy()
	lines[14] = tHandshake(15, "2026-09-24T11:10:01Z", 4, "refused", true, false)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}))
}

func TestTunnelDeniedButServed(t *testing.T) {
	lines := tunnelHealthy()
	// Connection 3 was denied and then closed as if it had been served.
	lines[12] = tClose(13, "2026-09-24T11:10:00Z", 3, "eof", 3)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"acl-before-serve", "3"})
}

func TestTunnelDeniedAndLingering(t *testing.T) {
	// Connection 8 was denied a minute ago, inside the lifetime cap but well
	// past the grace, and has not been closed as refused.
	healthy := tunnelHealthy()
	conn8 := func(at string) []string {
		return []string{tAccept(0, at, 8), tACL(0, at, 8, "deny"), tHandshakeChain(0, at, 8, "ok", false, true, gtChainOther)}
	}
	// Spliced in before connection 6, three minutes before now.
	lines := append(append(append([]string{}, healthy[:18]...), conn8("2026-09-24T11:57:00Z")...), healthy[18:]...)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"acl-before-serve", "8"})
	// Denied a second ago and not yet closed: inside the grace, nothing.
	lines = append(append([]string{}, healthy...), conn8("2026-09-24T11:59:59Z")...)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}))
	// With a grace of half a second it is overdue again, and so is the
	// healthy tree's connection 7, whose acl line is one second late.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{ACLGrace: 500 * time.Millisecond}), Finding{"acl-before-serve", "7"}, Finding{"acl-before-serve", "8"})
}

func TestTunnelServedWithoutACL(t *testing.T) {
	lines := tunnelHealthy()
	// Connection 1 has no acl line and was closed as served.
	lines = append(lines[:3], lines[4:]...)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"acl-before-serve", "1"})
	// Connection 6 has no acl line, is still open, and its handshake was
	// two minutes ago: the decision is overdue.
	lines = tunnelHealthy()
	lines = append(lines[:20], lines[21:]...)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"acl-before-serve", "6"})
	// A shutdown close after an ok handshake with no acl is still served
	// without a decision.
	lines = tunnelHealthy()
	lines = append(lines[:3], lines[4:]...)
	lines[3] = tClose(5, "2026-09-24T11:00:09Z", 1, "shutdown", 8000)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"acl-before-serve", "1"})
}

func TestTunnelLifetimeCap(t *testing.T) {
	lines := tunnelHealthy()
	// Connection 2 closed after 302.1 s against a 300 s cap and a 2 s margin.
	lines[8] = tClose(9, "2026-09-24T11:05:10Z", 2, "lifetime", 302100)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"lifetime-cap", "2"})
	// Exactly at the cap plus margin is not over it.
	lines[8] = tClose(9, "2026-09-24T11:05:10Z", 2, "lifetime", 302000)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}))
	// Connection 6 accepted at 11:58:00 and open at 12:00:00 is inside a
	// 300 s cap; against a 100 s cap it has outlived it.
	lines = tunnelHealthy()
	lines[0] = tStart(1, "2026-09-24T11:00:00Z", 1, strings.Replace(tunnelConfig, `"lifetime_cap_seconds":300`, `"lifetime_cap_seconds":100`, 1))
	got := tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{})
	// Connection 2's 300.4 s close is now also over the 100 s cap.
	tunnelWant(t, got, Finding{"lifetime-cap", "2"}, Finding{"lifetime-cap", "6"})
	// A cap of 0 is no cap: nothing to check.
	lines = tunnelHealthy()
	lines[0] = tStart(1, "2026-09-24T11:00:00Z", 1, strings.Replace(tunnelConfig, `"lifetime_cap_seconds":300`, `"lifetime_cap_seconds":0`, 1))
	lines[8] = tClose(9, "2026-09-24T11:05:10Z", 2, "eof", 9000000)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}))
	// The margin is the member's own value.
	lines = tunnelHealthy()
	lines[8] = tClose(9, "2026-09-24T11:05:10Z", 2, "lifetime", 300400)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{LifetimeMargin: 100 * time.Millisecond}), Finding{"lifetime-cap", "2"})
}

func TestTunnelListenerExpected(t *testing.T) {
	root := tunnelTree(t, tunnelHealthy()...)
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectListen: "localhost:9443"}), Finding{"listener-expected", "localhost:8443"})
}

// TestTunnelTargetExpected: the backend target the start line names is the
// one the operator expects, compared exactly, with the recorded target as
// subject; no expectation, no check (the unit refuses to start without one,
// as for the listener).
func TestTunnelTargetExpected(t *testing.T) {
	root := tunnelTree(t, tunnelHealthy()...)
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectTarget: "localhost:8080"}))
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectTarget: "localhost:9080"}), Finding{"target-expected", "localhost:8080"})
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectTarget: "127.0.0.1:8080"}), Finding{"target-expected", "localhost:8080"})
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectTarget: "localhost:8080 "}), Finding{"target-expected", "localhost:8080"})
	// Beside the listener, each with its own subject.
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectListen: "localhost:9443", ExpectTarget: "localhost:9080"}), Finding{"listener-expected", "localhost:8443"}, Finding{"target-expected", "localhost:8080"})
}

// TestTunnelProxyProtocolExpected: what the backend is handed ahead of each
// connection, the start line's proxy_protocol, is the mode the operator
// expects, off when nothing was said; the recorded mode is the subject.
// The check is never absent.
func TestTunnelProxyProtocolExpected(t *testing.T) {
	// The healthy start line records off.
	root := tunnelTree(t, tunnelHealthy()...)
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{}))
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectProxyProtocol: "off"}))
	for _, want := range []string{"conn", "tls", "tls-full"} {
		tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectProxyProtocol: want}), Finding{"proxy-protocol-expected", "off"})
	}
	// A start line under tls-full, the mode that hands the backend the
	// client's certificate: a finding unless that is exactly what was
	// expected.
	lines := tunnelHealthy()
	lines[0] = strings.Replace(lines[0], `"proxy_protocol":"off"`, `"proxy_protocol":"tls-full"`, 1)
	root = tunnelTree(t, lines...)
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{}), Finding{"proxy-protocol-expected", "tls-full"})
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectProxyProtocol: "off"}), Finding{"proxy-protocol-expected", "tls-full"})
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectProxyProtocol: "tls"}), Finding{"proxy-protocol-expected", "tls-full"})
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectProxyProtocol: "tls-full"}))
	// A start line that does not say is a malformed line (gtreader_test.go):
	// the trace is unreadable and every check fails, this one among them.
	lines[0] = strings.Replace(lines[0], `"proxy_protocol":"tls-full",`, ``, 1)
	root = tunnelTree(t, lines...)
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectProxyProtocol: "off"}), tunnelAllFail("0000000001/0000000001.trace:1")...)
}

func TestTunnelParseExpectProxyProtocol(t *testing.T) {
	if got, err := parseExpectProxyProtocol(""); err != nil || got != "off" {
		t.Fatalf("empty parsed %q, %v; want off", got, err)
	}
	for _, mode := range []string{"off", "conn", "tls", "tls-full"} {
		if got, err := parseExpectProxyProtocol(mode); err != nil || got != mode {
			t.Errorf("%q parsed %q, %v", mode, got, err)
		}
	}
	for _, bad := range []string{"OFF", " off", "off ", "tls-full\n", "off,conn", "v2", "none", "true"} {
		if got, err := parseExpectProxyProtocol(bad); err == nil {
			t.Errorf("%q parsed as %q", bad, got)
		}
	}
}

func TestTunnelACLExpected(t *testing.T) {
	root := tunnelTree(t, tunnelHealthy()...)
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectACL: []string{"allow-cn:client.example"}}))
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectACL: []string{"allow-cn:other.example"}}), Finding{"acl-expected", "allow-cn:client.example"})
	// A superset or a subset of the start line's set is a mismatch.
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectACL: []string{"allow-all", "allow-cn:client.example"}}), Finding{"acl-expected", "allow-cn:client.example"})
	hash := strings.Repeat("00", 32)
	lines := tunnelHealthy()
	lines[0] = tStart(1, "2026-09-24T11:00:00Z", 1, strings.Replace(tunnelConfig, `"acl":["allow-cn:client.example"]`, `"acl":["allow-cn:a","allow-cn:b","policy:`+hash+`"]`, 1))
	root = tunnelTree(t, lines...)
	// Under that rule set the chains presented match no allow-cn and the
	// policy it names is on no disk, so every acl line is re-judged as
	// one the member cannot confirm (substance.go): the substance
	// findings stand beside the expectation's.
	substance := []Finding{{"acl-substance", "1"}, {"acl-substance", "2"}, {"acl-substance", "3"}, {"acl-substance", "6"}}
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectACL: []string{"allow-cn:a", "allow-cn:b"}}), append([]Finding{{"acl-expected", "allow-cn:a,allow-cn:b,policy:" + hash}}, substance...)...)
	// Compared as sets: the expectation's order and repetition do not matter.
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectACL: []string{"policy:" + hash, "allow-cn:b", "allow-cn:a", "allow-cn:b"}}), substance...)
	// The subject is the start line's list, cut to 256 bytes.
	var pins []string
	for i := 0; i < 4; i++ {
		pins = append(pins, fmt.Sprintf(`"allow-spki-pin:sha256:%s"`, strings.Repeat(fmt.Sprint(i), 64)))
	}
	lines[0] = tStart(1, "2026-09-24T11:00:00Z", 1, strings.Replace(tunnelConfig, `"acl":["allow-cn:client.example"]`, `"acl":[`+strings.Join(pins, ",")+`]`, 1))
	root = tunnelTree(t, lines...)
	joined := strings.ReplaceAll(strings.Join(pins, ","), `"`, "")
	if len(joined) <= 256 {
		t.Fatalf("the list is %d bytes; the test needs one over 256", len(joined))
	}
	// In pin mode no presented leaf's key is pinned: every verified
	// handshake and every allow is re-judged against the pins and fails.
	pinned := []Finding{{"handshake-substance", "1"}, {"handshake-substance", "2"}, {"handshake-substance", "3"}, {"handshake-substance", "6"}, {"handshake-substance", "7"}, {"acl-substance", "1"}, {"acl-substance", "2"}, {"acl-substance", "6"}}
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{ExpectACL: []string{"allow-all"}}), append([]Finding{{"acl-expected", joined[:256]}}, pinned...)...)
}

func TestTunnelParseExpectACL(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	got, err := parseExpectACL("policy:" + hash + ",allow-cn:b,allow-cn:a,allow-cn:b")
	if err != nil || fmt.Sprint(got) != fmt.Sprint([]string{"allow-cn:a", "allow-cn:b", "policy:" + hash}) {
		t.Fatalf("parsed %v, %v", got, err)
	}
	if got, err := parseExpectACL(""); err != nil || got != nil {
		t.Fatalf("empty parsed %v, %v", got, err)
	}
	for _, bad := range []string{"allow-cn:a,", ",allow-all", "allow-cn:a, allow-cn:b", "allow-cn:", "allow-everything", "policy:xyz", "allow-all\n"} {
		if got, err := parseExpectACL(bad); err == nil {
			t.Errorf("%q parsed as %v", bad, got)
		}
	}
}

func TestTunnelTickFresh(t *testing.T) {
	// The healthy tree's tick is one second before now.
	healthy := tunnelHealthy()
	tunnelWant(t, tunnelRun(t, tunnelTree(t, healthy...), TunnelChecks{}))
	// The newest tick 31 s old is stale under the default max-age of 30 s;
	// a max-age of a minute forgives it. The tick sits between connection
	// 6 (11:58:00) and connection 7 (11:59:59); no tick follows.
	lines := append(append(append([]string{}, healthy[:21]...), tTick(0, "2026-09-24T11:59:29Z")), healthy[21:23]...)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"tick-fresh", "2026-09-24T11:59:29Z"})
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{TickMaxAge: time.Minute}))
	// 30 s old is within it.
	lines = append(append(append([]string{}, healthy[:21]...), tTick(0, "2026-09-24T11:59:30Z")), healthy[21:23]...)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}))
	// No tick at all: the start line, an hour old, is the reference, and
	// the connection lines since do not refresh it.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, healthy[:23]...), TunnelChecks{}), Finding{"tick-fresh", "2026-09-24T11:00:00Z"})
	// A boot started 10 s ago with no tick yet is fresh.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, tStart(1, "2026-09-24T11:59:50Z", 1, tunnelConfig)), TunnelChecks{}))
}

func TestTunnelAcceptLoop(t *testing.T) {
	healthy := tunnelHealthy()
	const oom = "accept tcp 127.0.0.1:8443: too many open files"
	// with splices accept-error lines in after connection 6's lines
	// (11:58:00) and before connection 7's (11:59:59).
	with := func(errs ...string) []string {
		return append(append(append([]string{}, healthy[:21]...), errs...), healthy[21:]...)
	}
	// 20 s ago: within the window.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:40Z", oom, 5))...), TunnelChecks{}), Finding{"accept-loop", oom})
	// 30 s ago: still within it; 40 s ago: outside it, nothing.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:30Z", oom, 5))...), TunnelChecks{}), Finding{"accept-loop", oom})
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:20Z", oom, 5))...), TunnelChecks{}))
	// The window is the member's own value.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:40Z", oom, 5))...), TunnelChecks{TickMaxAge: 10 * time.Second}))
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:20Z", oom, 5))...), TunnelChecks{TickMaxAge: time.Minute}), Finding{"accept-loop", oom})
	// Two lines with the same error are one finding; two errors are two.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:40Z", oom, 5), tAcceptError(0, "2026-09-24T11:59:41Z", oom, 10))...), TunnelChecks{}), Finding{"accept-loop", oom})
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:40Z", oom, 5), tAcceptError(0, "2026-09-24T11:59:41Z", "accept tcp 127.0.0.1:8443: use of closed network connection", 10))...), TunnelChecks{}), Finding{"accept-loop", oom}, Finding{"accept-loop", "accept tcp 127.0.0.1:8443: use of closed network connection"})
	// A long error is cut to 64 bytes, on a rune boundary.
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:40Z", strings.Repeat("e", 70), 5))...), TunnelChecks{}), Finding{"accept-loop", strings.Repeat("e", 64)})
	tunnelWant(t, tunnelRun(t, tunnelTree(t, with(tAcceptError(0, "2026-09-24T11:59:40Z", strings.Repeat("e", 63)+"éx", 5))...), TunnelChecks{}), Finding{"accept-loop", strings.Repeat("e", 63)})
}

func TestTunnelConnInconsistent(t *testing.T) {
	lines := tunnelHealthy()
	// A handshake for a connection that was never accepted.
	lines = append(lines, tHandshake(24, "2026-09-24T11:59:59Z", 99, "ok", false, true))
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"conn-consistent", "99"})
	// A second accept of the same connection id.
	lines = tunnelHealthy()
	lines = append(lines, tAccept(24, "2026-09-24T11:59:59Z", 1))
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"conn-consistent", "1"})
	// A second close, an acl without an accept, a close without an accept.
	lines = tunnelHealthy()
	// The acl line without a handshake is also an allow the substance
	// rules cannot confirm (no chain to re-judge).
	lines = append(lines, tClose(24, "2026-09-24T11:59:59Z", 1, "eof", 1), tACL(25, "2026-09-24T11:59:59Z", 98, "allow"), tClose(26, "2026-09-24T11:59:59Z", 97, "eof", 1))
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), Finding{"conn-consistent", "1"}, Finding{"conn-consistent", "98"}, Finding{"conn-consistent", "97"}, Finding{"acl-substance", "98"})
}

func TestTunnelReadsTheCurrentBootOnly(t *testing.T) {
	root := t.TempDir()
	bad := tunnelHealthy()
	// The older boot's process is gone, as it is after a restart.
	bad[0] = strings.Replace(bad[0], `"pid":4242`, `"pid":4141`, 1)
	bad[2] = tHandshake(3, "2026-09-24T11:00:01Z", 1, "ok", false, false)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(bad...))
	good := tunnelHealthy()
	good[0] = tStart(1, "2026-09-24T11:00:00Z", 2, tunnelConfig)
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(good...))
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{}))
}

// tunnelBootFail is what a current boot that cannot be judged yields: every
// check over it fails, and trace-readable names where. trace-consistent
// compares what was read and boot-ambiguous asks the process table; neither
// is over the current boot.
func tunnelBootFail(subject string) []Finding {
	out := []Finding{{"trace-readable", subject}}
	for _, id := range (TunnelChecks{}).Identifiers() {
		if id != "trace-readable" && id != "trace-consistent" && id != "boot-ambiguous" && id != "boot-ended" {
			out = append(out, Finding{id, ""})
		}
	}
	return out
}

// tunnelAllFail is what an unreadable trace yields: tunnelBootFail, and
// trace-consistent, which could not compare anything.
func tunnelAllFail(subject string) []Finding {
	return append(tunnelBootFail(subject), Finding{"trace-consistent", ""})
}

func TestTunnelUnreadableTraceFailsEveryCheck(t *testing.T) {
	// No root configured.
	tunnelWant(t, tunnelRun(t, "", TunnelChecks{}), tunnelAllFail("gt")...)
	// Root missing.
	tunnelWant(t, tunnelRun(t, filepath.Join(t.TempDir(), "gt"), TunnelChecks{}), tunnelAllFail("gt")...)
	// Root present but no boot.
	tunnelWant(t, tunnelRun(t, t.TempDir(), TunnelChecks{}), tunnelAllFail("gt")...)
	// A stray entry under the root.
	root := tunnelTree(t, tunnelHealthy()...)
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{}), tunnelAllFail("README")...)
	// A malformed line in the current boot.
	lines := tunnelHealthy()
	lines[3] = strings.Replace(lines[3], `"decision":"allow"`, `"decision":"yes"`, 1)
	tunnelWant(t, tunnelRun(t, tunnelTree(t, lines...), TunnelChecks{}), tunnelAllFail("0000000001/0000000001.trace:4")...)
	// A sequence gap, written without renumbering.
	lines = tunnelHealthy()
	lines = append(lines[:4], lines[5:]...)
	root = t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines...))
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{}), tunnelAllFail("0000000001/0000000001.trace:5")...)
	// The current boot has no start line yet (an empty boot directory).
	root = tunnelTree(t, tunnelHealthy()...)
	if err := os.Mkdir(filepath.Join(root, "0000000002"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The empty boot cannot be shown dead and the older boot's process
	// is live: ambiguous as well.
	tunnelWant(t, tunnelRun(t, root, TunnelChecks{}), append(tunnelBootFail("0000000002"), Finding{"boot-ambiguous", "0000000001,0000000002"})...)
	// The expectations, when configured, fail with the rest.
	all := append(tunnelAllFail("gt"), Finding{"listener-expected", ""})
	tunnelWant(t, tunnelRun(t, "", TunnelChecks{ExpectListen: "localhost:8443"}), all...)
	all = append(tunnelAllFail("gt"), Finding{"target-expected", ""})
	tunnelWant(t, tunnelRun(t, "", TunnelChecks{ExpectTarget: "localhost:8080"}), all...)
	all = append(tunnelAllFail("gt"), Finding{"acl-expected", ""})
	tunnelWant(t, tunnelRun(t, "", TunnelChecks{ExpectACL: []string{"allow-all"}}), all...)
	// proxy-protocol-expected is never absent, so it is in tunnelAllFail
	// already, whatever the expectation.
	tunnelWant(t, tunnelRun(t, "", TunnelChecks{ExpectProxyProtocol: "tls-full"}), tunnelAllFail("gt")...)
	// And tick-fresh is among the rest: an unreadable trace, or a current
	// boot with no start line, has no reference to judge by.
	for _, f := range tunnelAllFail("gt") {
		if f.Check == "tick-fresh" {
			return
		}
	}
	t.Fatal("tick-fresh is not among the checks an unreadable trace fails")
}

// TestTunnelRunJudgesTheRing is the wiring of the checks this member makes
// beyond its own surface: the other surfaces against their owners'
// accounts, every boot's process, and the trace against what was read
// last cycle.
func TestTunnelRunJudgesTheRing(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, tunnelNow)
	root := tunnelTree(t, tunnelHealthy()...)
	checks := TunnelChecks{Live: procLiveness(blTable(t, 4242))}
	peers := map[string]PeerView{}
	for _, o := range []string{"admin", "material"} {
		peers[o] = PeerView{Verdict: VerdictAlive, Checks: surfaceIdentifiers(o)}
	}
	st := &State{}
	tunnelWant(t, tunnelSorted(checks.Run(&Config{TracesRoot: root, Now: now}, st, peers)))
	// The admin member stopped listing shutdown-authorized.
	peers["admin"] = PeerView{Verdict: VerdictAlive, Checks: []string{"status-listener-bound", "pprof-cmdline-redacted", "status-listener-up"}}
	tunnelWant(t, tunnelSorted(checks.Run(&Config{TracesRoot: root, Now: now}, st, peers)), Finding{"surface-disagree", "admin:shutdown-authorized"})
	// The material surface fails here (tickets on, no re-verification)
	// and the material member's fault does not say so.
	lines := tunnelHealthy()
	lines[0] = tStart(1, "2026-09-24T11:00:00Z", 1, strings.Replace(tunnelConfig, `"verify_on_resume":true`, `"verify_on_resume":false`, 1))
	root = tunnelTree(t, lines...)
	peers["admin"] = PeerView{Verdict: VerdictAlive, Checks: surfaceIdentifiers("admin")}
	tunnelWant(t, tunnelSorted(checks.Run(&Config{TracesRoot: root, Now: now}, &State{}, peers)), Finding{"surface-disagree", "material:resumption-bound"})
	// A second boot whose process is live beside the current one.
	root = tunnelTree(t, tunnelHealthy()...)
	second := tunnelHealthy()
	second[0] = strings.Replace(tStart(1, "2026-09-24T11:30:00Z", 2, tunnelConfig), `"pid":4242`, `"pid":4343`, 1)
	for i := range second[1:] {
		second[i+1] = tReAt(second[i+1], "2026-09-24T11:59:59Z")
	}
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(tRenumber(second)...))
	table := t.TempDir()
	for _, pid := range []string{"4242", "4343"} {
		if err := os.Mkdir(filepath.Join(table, pid), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := tunnelSorted(TunnelChecks{Live: procLiveness(table)}.Run(&Config{TracesRoot: root, Now: now}, &State{}, peers))
	tunnelWant(t, got, Finding{"boot-ambiguous", "0000000001,0000000002"})
	// The current boot rewritten under this member between two cycles.
	root = tunnelTree(t, tunnelHealthy()...)
	st = &State{}
	tunnelWant(t, tunnelSorted(checks.Run(&Config{TracesRoot: root, Now: now}, st, peers)))
	lines = tunnelHealthy()
	lines[1] = strings.Replace(lines[1], `"remote":"10.0.0.7:50001"`, `"remote":"10.0.0.9:50001"`, 1)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(tRenumber(lines)...))
	tunnelWant(t, tunnelSorted(checks.Run(&Config{TracesRoot: root, Now: now}, st, peers)), Finding{"trace-consistent", "0000000001/0000000001.trace"})
}

func tunnelSorted(got []Finding) []Finding {
	sort.Slice(got, func(i, j int) bool {
		if got[i].Check != got[j].Check {
			return got[i].Check < got[j].Check
		}
		return got[i].Subject < got[j].Subject
	})
	return got
}
