package main

// localchecks_test.go proves the admin member's surface checks against
// synthetic gt/ trees written by hand in the exact ringtrace format and a
// synthetic process table standing for /proc. One healthy tree yields
// nothing; one tree per violation yields exactly the expected finding; and
// the unreadable trees yield a finding for every check because no check
// could run.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const adminNow = "2026-09-24T12:00:00Z"

// adminSurface is what the start line says of the status surface.
type adminSurface struct {
	listen        string // a JSON string literal, or null
	clientCert    bool
	pprofRedacted bool
	shutdownCert  bool
}

// loopback is the healthy surface: loopback, redacting, gated.
var loopback = adminSurface{listen: `"127.0.0.1:6060"`, pprofRedacted: true, shutdownCert: true}

func adminConfig(s adminSurface) string {
	return fmt.Sprintf(`{"mode":"server","listen":"localhost:8443","target":"localhost:8080","proxy_protocol":"off","status_listen":%s,"status_client_cert":%t,"pprof_cmdline_redacted":%t,"shutdown_requires_client_cert":%t,"session_tickets":false,"verify_on_resume":true,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":"applied","sandbox_accepted":null,"material":[]}`, s.listen, s.clientCert, s.pprofRedacted, s.shutdownCert)
}

func aHdr(kind string, seq int, at string) string {
	return fmt.Sprintf(`{"kind":"%s","version":1,"sequence":%d,"at":"%s"`, kind, seq, at)
}

func aStart(seq int, at string, boot int, config string) string {
	return fmt.Sprintf(`%s,"boot":%d,"pid":4242,"config":%s}`, aHdr("start", seq, at), boot, config)
}

// aShutdown writes a shutdown line; peer is a JSON string literal or null.
func aShutdown(seq int, at string, source string, authorized bool, peer string) string {
	return fmt.Sprintf(`%s,"source":"%s","authorized":%t,"peer":%s,"detail":"requested"}`, aHdr("shutdown", seq, at), source, authorized, peer)
}

// aTick writes a tick line: the header and nothing else.
func aTick(seq int, at string) string {
	return aHdr("tick", seq, at) + "}"
}

// aRefusal writes a refusal line: the proxy refuses to serve until
// restart because source failed with err.
func aRefusal(seq int, at string, source, err string) string {
	return fmt.Sprintf(`%s,"source":"%s","error":"%s"}`, aHdr("refusal", seq, at), source, err)
}

// TestAdminStatusListenerUp: a refusal line naming the status listener is
// the listener's death, which the proxy records once and which stands for
// the rest of the boot: status-listener-up fails with the error text as
// subject, bounded to 64 bytes, once per distinct text, in every later
// cycle of the boot; a boot with no such line passes.
func TestAdminStatusListenerUp(t *testing.T) {
	proc := adminProc(t, cleanArgv...)
	const errText = "accept tcp 127.0.0.1:6060: use of closed network connection"
	lines := append(adminHealthy(), aRefusal(0, "2026-09-24T11:32:00Z", "status-listener", errText))
	root := adminTree(t, lines...)
	checks := AdminChecks{Cmdline: procCmdline(proc)}
	adminWant(t, adminRun(t, root, checks), Finding{"status-listener-up", errText})
	// The line stands: the next cycle finds it again, with a later tick.
	adminWant(t, adminRun(t, root, checks), Finding{"status-listener-up", errText})
	// A second line with the same text is one finding; a long text is cut.
	long := strings.Repeat("e", 100)
	lines = append(lines, aRefusal(0, "2026-09-24T11:33:00Z", "status-listener", errText), aRefusal(0, "2026-09-24T11:34:00Z", "status-listener", long))
	adminWant(t, adminRun(t, adminTree(t, lines...), checks), Finding{"status-listener-up", errText}, Finding{"status-listener-up", long[:64]})
	// Without the line, nothing.
	adminWant(t, adminRun(t, adminTree(t, adminHealthy()...), checks))
}

// aFreshTick is the tick one second before adminNow that adminTree appends
// to every boot, so that tick-fresh holds over trees whose lines are an
// hour old.
const aFreshTick = "2026-09-24T11:59:59Z"

// adminHealthy is a boot with a loopback status listener that redacts
// pprof's cmdline and gates /_shutdown, an authorized signal shutdown and
// an authorized status-endpoint shutdown with a peer.
func adminHealthy() []string {
	return []string{
		aStart(1, "2026-09-24T11:00:00Z", 1, adminConfig(loopback)),
		aShutdown(2, "2026-09-24T11:30:00Z", "signal", true, "null"),
		aShutdown(3, "2026-09-24T11:31:00Z", "status-endpoint", true, `"CN=operator"`),
	}
}

// aRenumber rewrites each line's sequence to its position.
func aRenumber(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		s := strings.Index(line, `"sequence":`) + len(`"sequence":`)
		e := s + strings.Index(line[s:], ",")
		out[i] = line[:s] + fmt.Sprint(i+1) + line[e:]
	}
	return out
}

func adminTree(t *testing.T, lines ...string) string {
	t.Helper()
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(aRenumber(aWithTick(lines))...))
	return root
}

// aWithTick is lines followed by the fresh tick, in a new slice.
func aWithTick(lines []string) []string {
	return append(append([]string{}, lines...), aTick(0, aFreshTick))
}

// adminProc builds a process table holding pid 4242 with the given argv.
func adminProc(t *testing.T, argv ...string) string {
	t.Helper()
	proc := t.TempDir()
	dir := filepath.Join(proc, strconv.Itoa(4242))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b []byte
	for _, a := range argv {
		b = append(append(b, a...), 0)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return proc
}

var cleanArgv = []string{"ghostunnel", "server", "--listen", "localhost:8443", "--target", "localhost:8080", "--keystore", "/etc/gt/keystore.p12", "--status", "127.0.0.1:6060"}

func adminRun(t *testing.T, root string, checks AdminChecks) []Finding {
	t.Helper()
	now, err := time.Parse(time.RFC3339, adminNow)
	if err != nil {
		t.Fatal(err)
	}
	if checks.StartTime == nil {
		// The process the trees name started when its start line says.
		checks.StartTime = adminStartedAt("2026-09-24T11:00:00Z")
	}
	if checks.Live == nil {
		// The trace's pid 4242 is live in the table: the highest boot's
		// process must read live.
		checks.Live = procLiveness(blTable(t, 4242))
	}
	got := checks.Run(&Config{TracesRoot: root, Now: now}, &State{}, nil)
	sort.Slice(got, func(i, j int) bool {
		if got[i].Check != got[j].Check {
			return got[i].Check < got[j].Check
		}
		return got[i].Subject < got[j].Subject
	})
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

func adminWant(t *testing.T, got []Finding, want ...Finding) {
	t.Helper()
	for _, fs := range [][]Finding{got, want} {
		fs := fs
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].Check != fs[j].Check {
				return fs[i].Check < fs[j].Check
			}
			return fs[i].Subject < fs[j].Subject
		})
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings\n got %v\nwant %v", got, want)
	}
}

// adminStartedAt is a start-time reader that says every process started
// at the given moment.
func adminStartedAt(at string) startTimeReader {
	started, err := time.Parse(time.RFC3339, at)
	return func(int64) (time.Time, error) { return started, err }
}

func TestAdminIdentifiers(t *testing.T) {
	want := []string{"trace-readable", "status-listener-bound", "pprof-cmdline-redacted", "shutdown-authorized", "status-listener-up", "cmdline-carries-no-secret", "proxy-process-alive", "tick-fresh", "trace-consistent", "boot-ambiguous", "boot-ended"}
	if got := (AdminChecks{}).Identifiers(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("identifiers %v, want %v", got, want)
	}
	ring := (AdminChecks{}).RingIdentifiers()
	if fmt.Sprint(ring) != fmt.Sprint([]string{"surface-disagree:material", "surface-disagree:tunnel"}) {
		t.Fatalf("ring identifiers %v", ring)
	}
}

func TestAdminHealthyTreeYieldsNothing(t *testing.T) {
	root := adminTree(t, adminHealthy()...)
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(adminProc(t, cleanArgv...))}))
}

func TestAdminTickFresh(t *testing.T) {
	// The healthy tree without adminTree's fresh tick: the newest line is
	// the shutdown at 11:31, but the reference is the start line, an hour
	// before now, and the member's own -tick-max-age is what forgives it.
	proc := adminProc(t, cleanArgv...)
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(aRenumber(adminHealthy())...))
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(proc)}), Finding{"tick-fresh", "2026-09-24T11:00:00Z"})
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(proc), TunnelMargins: surfaceMargins{TickMaxAge: 2 * time.Hour}}))
	// A tick 31 s old is stale; 30 s old is not.
	root = t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(aRenumber(append(adminHealthy(), aTick(0, "2026-09-24T11:59:29Z")))...))
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(proc)}), Finding{"tick-fresh", "2026-09-24T11:59:29Z"})
	root = t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(aRenumber(append(adminHealthy(), aTick(0, "2026-09-24T11:59:30Z")))...))
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(proc)}))
}

func TestAdminStatusListenerBound(t *testing.T) {
	proc := adminProc(t, cleanArgv...)
	cases := []struct {
		listen  string
		cert    bool
		subject string // empty: no finding
	}{
		{"null", false, ""},
		{`"127.0.0.1:6060"`, false, ""},
		{`"localhost:6060"`, false, ""},
		{`"[::1]:6060"`, false, ""},
		{`"http://127.0.0.1:6060"`, false, ""},
		{`"https://[::1]:6060"`, false, ""},
		{`"0.0.0.0:6060"`, false, "0.0.0.0:6060"},
		{`"0.0.0.0:6060"`, true, ""},
		{`":6060"`, false, ":6060"},
		{`"10.0.0.5:6060"`, false, "10.0.0.5:6060"},
		{`"https://10.0.0.5:6060"`, false, "https://10.0.0.5:6060"},
		{`"unix:/run/ghostunnel-status.sock"`, false, "unix:/run/ghostunnel-status.sock"},
		{`"systemd:status"`, false, "systemd:status"},
		{`"launchd:status"`, false, "launchd:status"},
		{`"127.0.0.1"`, false, "127.0.0.1"},
		{`""`, false, ""},
	}
	for _, c := range cases {
		t.Run(c.listen, func(t *testing.T) {
			s := loopback
			s.listen, s.clientCert = c.listen, c.cert
			lines := adminHealthy()
			lines[0] = aStart(1, "2026-09-24T11:00:00Z", 1, adminConfig(s))
			got := adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)})
			if c.listen == `""` {
				// An empty listener string names nothing loopback and no
				// certificate: bound to nothing that can be judged.
				adminWant(t, got, Finding{"status-listener-bound", ""})
				return
			}
			if c.subject == "" {
				adminWant(t, got)
			} else {
				adminWant(t, got, Finding{"status-listener-bound", c.subject})
			}
		})
	}
}

func TestAdminPprofCmdlineRedacted(t *testing.T) {
	proc := adminProc(t, cleanArgv...)
	s := loopback
	s.pprofRedacted = false
	lines := adminHealthy()
	lines[0] = aStart(1, "2026-09-24T11:00:00Z", 1, adminConfig(s))
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), Finding{"pprof-cmdline-redacted", ""})
	// With no status surface nothing serves pprof, so nothing to redact.
	s.listen = "null"
	lines[0] = aStart(1, "2026-09-24T11:00:00Z", 1, adminConfig(s))
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}))
}

func TestAdminShutdownAuthorized(t *testing.T) {
	proc := adminProc(t, cleanArgv...)
	// /_shutdown served without requiring a client certificate.
	s := loopback
	s.shutdownCert = false
	lines := adminHealthy()
	lines[0] = aStart(1, "2026-09-24T11:00:00Z", 1, adminConfig(s))
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), Finding{"shutdown-authorized", "not-gated"})
	// With no status surface /_shutdown is not served at all.
	s.listen = "null"
	lines[0] = aStart(1, "2026-09-24T11:00:00Z", 1, adminConfig(s))
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}))
	// Requests that were not authorized, or came unnamed.
	lines = adminHealthy()
	lines[1] = aShutdown(2, "2026-09-24T11:30:00Z", "signal", false, "null")
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), Finding{"shutdown-authorized", "signal"})
	lines = adminHealthy()
	lines[2] = aShutdown(3, "2026-09-24T11:31:00Z", "status-endpoint", false, `"CN=stranger"`)
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), Finding{"shutdown-authorized", "status-endpoint"})
	lines = adminHealthy()
	lines[2] = aShutdown(3, "2026-09-24T11:31:00Z", "status-endpoint", true, "null")
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), Finding{"shutdown-authorized", "status-endpoint:no-peer"})
	lines = adminHealthy()
	lines = append(lines, aShutdown(4, "2026-09-24T11:32:00Z", "ring-halt", false, "null"), aShutdown(5, "2026-09-24T11:33:00Z", "internal", true, "null"))
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), Finding{"shutdown-authorized", "ring-halt"})
}

func TestAdminCmdlineCarriesNoSecret(t *testing.T) {
	root := adminTree(t, adminHealthy()...)
	cases := []struct {
		name    string
		argv    []string
		subject string
	}{
		{"storepass separate", append(append([]string{}, cleanArgv...), "--storepass", "hunter2"), "--storepass"},
		{"storepass joined", append(append([]string{}, cleanArgv...), "--storepass=hunter2"), "--storepass"},
		{"pkcs11 pin separate", append(append([]string{}, cleanArgv...), "--pkcs11-pin", "1234"), "--pkcs11-pin"},
		{"pkcs11 pin joined", append(append([]string{}, cleanArgv...), "--pkcs11-pin=1234"), "--pkcs11-pin"},
		{"url with credentials", append(append([]string{}, cleanArgv...), "--metrics-url", "https://user:pw@metrics.example/push"), "url-credentials"},
		{"url with credentials joined", append(append([]string{}, cleanArgv...), "--metrics-url=https://user:pw@metrics.example/push"), "url-credentials"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(adminProc(t, c.argv...))}), Finding{"cmdline-carries-no-secret", c.subject})
		})
	}
	// A URL without credentials is fine; the flags' environment forms leave
	// nothing on the command line.
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(adminProc(t, append(append([]string{}, cleanArgv...), "--metrics-url", "https://metrics.example/push")...))}))
	// A command line that cannot be read has not been checked.
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(t.TempDir())}), Finding{"cmdline-carries-no-secret", "pid:4242"})
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(adminProc(t))}), Finding{"cmdline-carries-no-secret", "pid:4242"})
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline("")}), Finding{"cmdline-carries-no-secret", "pid:4242"})
}

// adminBootFail is what a current boot that cannot be judged yields: every
// check over it fails, and trace-readable names where. trace-consistent
// compares what was read and boot-ambiguous asks the process table; neither
// is over the current boot.
func adminBootFail(subject string) []Finding {
	out := []Finding{{"trace-readable", subject}}
	for _, id := range (AdminChecks{}).Identifiers() {
		if id != "trace-readable" && id != "trace-consistent" && id != "boot-ambiguous" && id != "boot-ended" {
			out = append(out, Finding{id, ""})
		}
	}
	return out
}

// adminAllFail is what an unreadable trace yields: adminBootFail, and
// trace-consistent, which could not compare anything.
func adminAllFail(subject string) []Finding {
	return append(adminBootFail(subject), Finding{"trace-consistent", ""})
}

func TestAdminUnreadableTraceFailsEveryCheck(t *testing.T) {
	proc := adminProc(t, cleanArgv...)
	adminWant(t, adminRun(t, "", AdminChecks{Cmdline: procCmdline(proc)}), adminAllFail("gt")...)
	adminWant(t, adminRun(t, filepath.Join(t.TempDir(), "gt"), AdminChecks{Cmdline: procCmdline(proc)}), adminAllFail("gt")...)
	adminWant(t, adminRun(t, t.TempDir(), AdminChecks{Cmdline: procCmdline(proc)}), adminAllFail("gt")...)
	root := adminTree(t, adminHealthy()...)
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(proc)}), adminAllFail("README")...)
	lines := adminHealthy()
	lines[2] = strings.Replace(lines[2], `"authorized":true`, `"authorized":"yes"`, 1)
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), adminAllFail("0000000001/0000000001.trace:3")...)
	// A start line without the admin fields cannot be read: the checks it
	// would feed have not run.
	lines = adminHealthy()
	lines[0] = strings.Replace(lines[0], `"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,`, "", 1)
	adminWant(t, adminRun(t, adminTree(t, lines...), AdminChecks{Cmdline: procCmdline(proc)}), adminAllFail("0000000001/0000000001.trace:1")...)
	root = adminTree(t, adminHealthy()...)
	if err := os.Mkdir(filepath.Join(root, "0000000002"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The empty boot cannot be shown dead and the older boot's process
	// is live: ambiguous as well.
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: procCmdline(proc)}), append(adminBootFail("0000000002"), Finding{"boot-ambiguous", "0000000001,0000000002"})...)
}

// TestAdminRunJudgesTheRing is the wiring of the checks this member makes
// beyond its own surface: the other surfaces against their owners'
// accounts, every boot's process, and the trace against what was read
// last cycle.
func TestAdminRunJudgesTheRing(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, adminNow)
	proc := adminProc(t, cleanArgv...)
	checks := AdminChecks{Cmdline: procCmdline(proc), StartTime: adminStartedAt("2026-09-24T11:00:00Z"), Live: procLiveness(blTable(t, 4242))}
	run := func(root string, st *State, peers map[string]PeerView) []Finding {
		got := checks.Run(&Config{TracesRoot: root, Now: now}, st, peers)
		sort.Slice(got, func(i, j int) bool {
			if got[i].Check != got[j].Check {
				return got[i].Check < got[j].Check
			}
			return got[i].Subject < got[j].Subject
		})
		return got
	}
	peers := map[string]PeerView{}
	for _, o := range []string{"tunnel", "material"} {
		peers[o] = PeerView{Verdict: VerdictAlive, Checks: surfaceIdentifiers(o)}
	}
	root := adminTree(t, adminHealthy()...)
	adminWant(t, run(root, &State{}, peers))
	// The tunnel member stopped listing lifetime-cap.
	peers["tunnel"] = PeerView{Verdict: VerdictAlive, Checks: []string{"conn-consistent", "handshake-verified", "resumption-verified", "acl-before-serve", "accept-loop", "handshake-substance", "acl-substance"}}
	adminWant(t, run(root, &State{}, peers), Finding{"surface-disagree", "tunnel:lifetime-cap"})
	peers["tunnel"] = PeerView{Verdict: VerdictAlive, Checks: surfaceIdentifiers("tunnel")}
	// The material surface fails here (tickets on, no re-verification)
	// and the material member's fault does not say so.
	s := loopback
	lines := adminHealthy()
	lines[0] = aStart(1, "2026-09-24T11:00:00Z", 1, strings.Replace(adminConfig(s), `"session_tickets":false,"verify_on_resume":true`, `"session_tickets":true,"verify_on_resume":false`, 1))
	adminWant(t, run(adminTree(t, lines...), &State{}, peers), Finding{"surface-disagree", "material:resumption-bound"})
	// A second boot whose process is live beside the current one.
	root = adminTree(t, adminHealthy()...)
	second := aStart(1, "2026-09-24T11:30:00Z", 2, adminConfig(loopback))
	second = strings.Replace(second, `"pid":4242`, `"pid":4343`, 1)
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(second, aTick(2, aFreshTick)))
	table := t.TempDir()
	for _, pid := range []string{"4242", "4343"} {
		if err := os.Mkdir(filepath.Join(table, pid), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	checks.Live = procLiveness(table)
	// The second boot's start line is at 11:30, which the injected start
	// time (11:00) is before by more than the allowance; and its process
	// is not in the command-line table either.
	adminWant(t, run(root, &State{}, peers), Finding{"boot-ambiguous", "0000000001,0000000002"}, Finding{"proxy-process-alive", "pid:4343:started-before"}, Finding{"cmdline-carries-no-secret", "pid:4343"})
	checks.Live = procLiveness(blTable(t, 4242))
	// The current boot rewritten under this member between two cycles.
	root = adminTree(t, adminHealthy()...)
	st := &State{}
	adminWant(t, run(root, st, peers))
	lines = adminHealthy()
	lines[2] = strings.Replace(lines[2], `"CN=operator"`, `"CN=operatoR"`, 1)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(aRenumber(aWithTick(lines))...))
	adminWant(t, run(root, st, peers), Finding{"trace-consistent", "0000000001/0000000001.trace"})
}
