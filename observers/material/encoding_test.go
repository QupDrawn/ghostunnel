package main

// encoding_test.go covers the encoding rules of SPEC 3 directly, the two
// procedure-V cases the fixture set says it cannot carry (V1 and T1's
// never-run grace) by editing a copy of a fixture, and the record of when
// this observer first ran (<own>/since), which no fixture carries either.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleHeartbeat = `{"kind":"heartbeat","version":1,"observer":"tunnel","sequence":44,"timestamp":"2026-09-20T10:07:20Z","cadence_seconds":10,"checks":["a","b"],"check_count":2,"observed":{"admin":null,"material":"30e15b46816381d344497d193a7f2efc0777d6bdad5a5114409b373dcce3c74d","super":null},"previous":"6cb89fa9407ea71967f51fe2c4362a8c13f10a4e21791ffaff74f3f9d319559c","boot":null,"stop":false}`

var sampleMembers = []string{"admin", "material", "super", "tunnel"}

func TestHashCoversTrailingLineFeed(t *testing.T) {
	// SPEC 3.5: the hash is over the bytes on disk, line feed included.
	if sha256Hex([]byte(sampleHeartbeat)) == sha256Hex([]byte(sampleHeartbeat+"\n")) {
		t.Fatal("hash ignores the trailing line feed")
	}
	if sha256Hex([]byte("")) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("sha256 of empty input is wrong")
	}
}

func TestClassifyByPrefix(t *testing.T) {
	cases := map[string]Kind{
		`{"kind":"heartbeat",`:                 KindHeartbeat,
		`{"kind":"heartbeat","version":1}`:     KindHeartbeat,
		`{"kind":"fault","version":1}`:         KindFault,
		`{"kind":"halt",`:                      KindHalt,
		`{ "kind":"heartbeat",`:                "",
		`{"kind": "heartbeat",`:                "",
		`{"version":1,"kind":"heartbeat",`:     "",
		"\xEF\xBB\xBF{\"kind\":\"heartbeat\",": "",
		`garbage`:                              "",
		``:                                     "",
	}
	for in, want := range cases {
		if got := classify([]byte(in)); got != want {
			t.Errorf("classify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseHeartbeatStrict(t *testing.T) {
	if _, err := parseHeartbeat([]byte(sampleHeartbeat), sampleMembers); err != nil {
		t.Fatalf("valid heartbeat rejected: %v", err)
	}
	if _, err := parseHeartbeat([]byte(sampleHeartbeat+"\n"), sampleMembers); err != nil {
		t.Fatalf("trailing line feed rejected: %v", err)
	}
	bad := map[string]string{
		"two line feeds":       sampleHeartbeat + "\n\n",
		"trailing garbage":     sampleHeartbeat + "x",
		"unknown key":          strings.Replace(sampleHeartbeat, `"stop":false}`, `"stop":false,"note":"x"}`, 1),
		"missing key":          strings.Replace(sampleHeartbeat, `,"stop":false`, ``, 1),
		"version 2":            strings.Replace(sampleHeartbeat, `"version":1`, `"version":2`, 1),
		"version float":        strings.Replace(sampleHeartbeat, `"version":1`, `"version":1.0`, 1),
		"sequence string":      strings.Replace(sampleHeartbeat, `"sequence":44`, `"sequence":"44"`, 1),
		"stop string":          strings.Replace(sampleHeartbeat, `"stop":false`, `"stop":"false"`, 1),
		"duplicate key":        strings.Replace(sampleHeartbeat, `"stop":false}`, `"stop":false,"stop":true}`, 1),
		"bad timestamp":        strings.Replace(sampleHeartbeat, `2026-09-20T10:07:20Z`, `2026-09-20 10:07:20`, 1),
		"upper-case hash":      strings.Replace(sampleHeartbeat, `"previous":"6cb`, `"previous":"6CB`, 1),
		"observed missing one": strings.Replace(sampleHeartbeat, `"admin":null,`, ``, 1),
		"observed extra":       strings.Replace(sampleHeartbeat, `"admin":null,`, `"admin":null,"tunnel":null,`, 1),
		"cadence zero":         strings.Replace(sampleHeartbeat, `"cadence_seconds":10`, `"cadence_seconds":0`, 1),
		"boot bad keys":        strings.Replace(sampleHeartbeat, `"boot":null`, `"boot":{"started":"2026-09-20T10:07:20Z"}`, 1),
		"kind fault":           strings.Replace(sampleHeartbeat, `{"kind":"heartbeat",`, `{"kind":"fault",`, 1),
		"bom":                  "\xEF\xBB\xBF" + sampleHeartbeat,
	}
	for name, in := range bad {
		if _, err := parseHeartbeat([]byte(in), sampleMembers); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEncodeHeartbeatRoundTrip(t *testing.T) {
	seq := int64(41)
	prev := "6cb89fa9407ea71967f51fe2c4362a8c13f10a4e21791ffaff74f3f9d319559c"
	hb := &Heartbeat{
		Observer: "tunnel", Sequence: 42, Timestamp: "2026-09-20T10:07:20Z", CadenceSeconds: 10,
		Checks: []string{"x"}, CheckCount: 1,
		Observed: map[string]*string{"admin": nil, "material": &prev, "super": nil},
		Previous: &prev, Boot: &BootRecord{Started: "2026-09-20T10:07:00Z", ResumedFrom: &seq},
	}
	b, err := encodeHeartbeat(hb)
	if err != nil {
		t.Fatal(err)
	}
	if classify(b) != KindHeartbeat {
		t.Fatalf("encoded heartbeat lacks the marker: %q", b[:24])
	}
	if b[len(b)-1] != '\n' || b[len(b)-2] == '\n' {
		t.Fatal("encoded heartbeat must end in exactly one line feed")
	}
	got, err := parseHeartbeat(b, sampleMembers)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if got.Sequence != 42 || got.Boot == nil || *got.Boot.ResumedFrom != 41 || got.Observed["material"] == nil {
		t.Fatalf("round trip lost fields: %+v", got)
	}
}

func TestFaultAndHaltStrict(t *testing.T) {
	f, err := encodeFault("tunnel", []Finding{{Check: "trace-fresh", Subject: "daily"}, {Check: "halts-readable"}})
	if err != nil {
		t.Fatal(err)
	}
	if classify(f) != KindFault {
		t.Fatal("fault marker")
	}
	pf, err := parseFault(f)
	if err != nil || len(pf.Failing) != 2 || pf.Failing[0].Check != "halts-readable" || pf.Failing[0].Subject != "" {
		t.Fatalf("fault round trip: %v %+v", err, pf)
	}
	if _, err := parseFault([]byte(`{"kind":"fault","version":1,"observer":"tunnel","failing":[]}` + "\n")); err == nil {
		t.Error("empty failing accepted")
	}
	h, err := encodeHalt(&Halt{Observer: "tunnel", Reason: "I7", Sequence: 3, When: "2026-09-20T10:07:20Z", Detail: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseHalt(h); err != nil {
		t.Fatalf("halt round trip: %v", err)
	}
	if _, err := parseHalt([]byte("garbage\n")); err == nil {
		t.Error("garbage halt accepted")
	}
}

// fixtureCopy copies one named fixture into a temp dir, as the fixture
// harness recreates it (recreateFixture: the manifest's directories, then
// the files), and returns a Config and State for its reader, as the
// harness would build them.
func fixtureCopy(t *testing.T, name string) (*Config, *State, string) {
	t.Helper()
	src := filepath.Join(fixtureRoot(), name)
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("fixture %s not present under %s: %v", name, fixtureRoot(), err)
	}
	_, tmp := recreateFixture(t, src)
	now, _ := time.Parse(time.RFC3339, "2026-09-20T10:07:25Z")
	cfg := &Config{
		Identity: "tunnel", Members: sampleMembers, Coordinator: "super", CopyAuthor: fixtureCopyAuthor,
		StoresRoot: filepath.Join(tmp, "stores"), TracesRoot: filepath.Join(tmp, "traces"),
		Window: 4, StaleSlack: 1, StagingStaleAfter: 60 * time.Second,
		MaxHeartbeatBytes: 8192, MaxFaultBytes: 8192, MaxHaltBytes: 8192,
		CadenceSeconds: 10, Now: now, Local: NoLocalChecks{}, DryRun: true,
	}
	st := &State{Started: now, Memory: map[string]string{}, Unchanged: map[string]time.Duration{}}
	// As the fixture harness supplies it: no fixture store carries a since
	// file, and a year before now makes a never-run schedule overdue.
	since := now.Add(-365 * 24 * time.Hour)
	st.ObservingSince = &since
	st.OwnStorePrivate = []string{}
	own := filepath.Join(cfg.StoresRoot, "tunnel", "heartbeat")
	names := listHeartbeats(t, own)
	for _, n := range names {
		st.Memory["tunnel/heartbeat/"+n] = hashFile(t, filepath.Join(own, n))
	}
	b, err := os.ReadFile(filepath.Join(own, names[len(names)-1]))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := parseHeartbeat(b, sampleMembers)
	if err != nil {
		t.Fatal(err)
	}
	st.HasBasis = true
	st.Basis = hb.Observed
	return cfg, st, tmp
}

func hasFinding(out *Outcome, check, subject string) bool {
	for _, f := range out.Failing {
		if f.Check == check && f.Subject == subject {
			return true
		}
	}
	return false
}

// SPEC 8.1 V1: a store that cannot be listed. The fixture set cannot carry
// it; here the store root is removed from a healthy ring.
func TestStoreUnreadableIsV1(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	if err := os.RemoveAll(filepath.Join(tmp, "stores", "material")); err != nil {
		t.Fatal(err)
	}
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdicts["material"] != VerdictUnknown {
		t.Errorf("verdict: want unknown, got %s", out.Verdicts["material"])
	}
	if !hasFinding(out, "store-readable", "material") {
		t.Errorf("store-readable(material) missing from %v", out.Failing)
	}
	if out.Publish.Observed["material"] != nil {
		t.Error("observed[material] must be null")
	}
	if !out.Halt.Writes || out.Halt.Reason != "store-readable" {
		t.Errorf("halt: %+v", out.Halt)
	}
}

// SPEC 7: an own store that cannot be read means the observer does not run.
func TestOwnStoreUnreadableRefuses(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	if err := os.RemoveAll(filepath.Join(tmp, "stores", "tunnel")); err != nil {
		t.Fatal(err)
	}
	if _, err := RunCycle(cfg, st); err == nil {
		t.Fatal("RunCycle ran without an own store")
	}
}

// SPEC 14.2 T1: a schedule that has never run is not stale until the
// deployment has been observed for period + margin, measured from when this
// observer first ran (State.ObservingSince) and never from the process start
// or the cycle count: a restart must not grant a never-scheduled job fresh
// grace, and a count of cycles is not a unit of time.
func TestTraceNeverRunGrace(t *testing.T) {
	cfg, st, _ := fixtureCopy(t, "healthy-ring")
	cfg.Traces = []TraceSchedule{{Schedule: "daily", Period: 86400 * time.Second, Margin: 600 * time.Second, Deadline: time.Hour, Declared: []string{"x"}}}
	// Observed for 440 s: not yet due.
	since := cfg.Now.Add(-440 * time.Second)
	st.ObservingSince = &since
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(out, "trace-fresh", "daily") || hasFinding(out, "trace-coverage", "daily") {
		t.Errorf("never-run schedule reported before it was due: %v", out.Failing)
	}
	// One second short of period + margin: still not due.
	since = cfg.Now.Add(-(86400 + 600 - 1) * time.Second)
	st.ObservingSince = &since
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(out, "trace-fresh", "daily") {
		t.Errorf("never-run schedule reported one second early: %v", out.Failing)
	}
	// Exactly period + margin: overdue, whatever the process clock and the
	// cadence say. The process started this instant and the sequence times
	// the cadence is 44 s; neither is the clock.
	since = cfg.Now.Add(-(86400 + 600) * time.Second)
	st.ObservingSince = &since
	st.Started = cfg.Now
	cfg.CadenceSeconds = 1
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(out, "trace-fresh", "daily") {
		t.Errorf("overdue never-run schedule not reported: %v", out.Failing)
	}
	// A clock that cannot be read observes nothing: nothing is due on it,
	// and observing-since says why rather than the trace checks guessing.
	st.ObservingSince = nil
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(out, "trace-fresh", "daily") {
		t.Errorf("never-run schedule reported against an unreadable clock: %v", out.Failing)
	}
	if !hasFinding(out, "observing-since", "") {
		t.Errorf("unreadable clock not reported: %v", out.Failing)
	}
}

// The record of when this observer first ran is read by the timestamp parser
// every other timestamp in the tree goes through, and its file form is
// exactly what the writer produces: the timestamp of SPEC 3.1 and one line
// feed, nothing else. Anything else is not a record, and nil says so.
func TestObservingSinceParser(t *testing.T) {
	own := t.TempDir()
	p := filepath.Join(own, "since")
	if got := readObservingSince(own); got != nil {
		t.Errorf("an absent record read as %v", got)
	}
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("2026-09-21T11:00:00Z\n")
	want, _ := time.Parse(time.RFC3339, "2026-09-21T11:00:00Z")
	if got := readObservingSince(own); got == nil || !got.Equal(want) {
		t.Errorf("a well-formed record read as %v, want %s", got, want)
	}
	for bad, why := range map[string]string{
		"2026-09-21T11:00:00Z":        "no line feed",
		"2026-09-21T11:00:00Z\n\n":    "two line feeds",
		" 2026-09-21T11:00:00Z\n":     "leading whitespace",
		"2026-09-21T11:00:00Z \n":     "trailing whitespace",
		"2026-09-21T11:00:00Z\r\n":    "a carriage return",
		"2026-09-21T11:00:00Z\n2026":  "a second line",
		"2026-02-30T00:00:00Z\n":      "a date that does not exist",
		"2026-09-21T11:00:00z\n":      "a lowercase z",
		"2026-09-21T11:00:00.5Z\n":    "fractional seconds",
		"2026-09-21T11:00:00+00:00\n": "an offset",
		"2026-09-21 11:00:00\n":       "a missing T and Z",
		"21/09/2026 11:00:00\n":       "a different format",
		"now\n":                       "a word",
		"\n":                          "a line feed alone",
		"":                            "an empty file",
	} {
		write(bad)
		if got := readObservingSince(own); got != nil {
			t.Errorf("%s read as %v", why, got)
		}
	}
	// Anything but a regular file is not a record either.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := readObservingSince(own); got != nil {
		t.Errorf("a directory read as %v", got)
	}
}

// SPEC 7: the first start writes <own>/since, the timestamp of SPEC 3.1 and
// one line feed, through a staging file; every later start leaves it exactly
// as it was, readable or not. Refreshed on each start it would be uptime, and
// a schedule that is never scheduled would be granted fresh grace on every
// restart, which is the one case T1 exists to catch.
func TestObservingSinceWrittenOnce(t *testing.T) {
	cfg, _, tmp := fixtureCopy(t, "healthy-ring")
	own := filepath.Join(tmp, "stores", cfg.Identity)
	p := filepath.Join(own, "since")
	if _, err := os.Stat(p); err == nil {
		t.Fatal("the fixture already carries a since file")
	}
	before := time.Now().UTC().Truncate(time.Second)
	st, err := startUp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("the first start did not write since: %v", err)
	}
	if len(b) != len(timestampLayout)+1 || b[len(b)-1] != '\n' {
		t.Fatalf("since is %q, not a timestamp and one line feed", b)
	}
	ts, err := parseTimestamp(string(b[:len(b)-1]))
	if err != nil {
		t.Fatalf("since %q: %v", b, err)
	}
	if ts.Before(before) || ts.After(time.Now().UTC()) {
		t.Errorf("since %s is not the time of the first start", ts)
	}
	if st.ObservingSince == nil || !st.ObservingSince.Equal(ts) {
		t.Errorf("state carries %v, the file says %s", st.ObservingSince, ts)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Error("the staging file was left behind")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	st, err = startUp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	infoAgain, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(b) || !infoAgain.ModTime().Equal(info.ModTime()) {
		t.Errorf("the second start rewrote since: %q at %s, was %q at %s", again, infoAgain.ModTime(), b, info.ModTime())
	}
	if st.ObservingSince == nil || !st.ObservingSince.Equal(ts) {
		t.Errorf("the second start carries %v, the file says %s", st.ObservingSince, ts)
	}
	// A record that cannot be read is left alone too; observing-since
	// reports it, and nothing here guesses a new one.
	if err := os.WriteFile(p, []byte("not a time\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = startUp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again, err = os.ReadFile(p); err != nil || string(again) != "not a time\n" {
		t.Errorf("an unreadable since was rewritten to %q (%v)", again, err)
	}
	if st.ObservingSince != nil {
		t.Errorf("an unreadable since read as %v", st.ObservingSince)
	}
}

// SPEC 11.2: since and since.tmp are regular files a store root may hold,
// the reader's own root and every peer's, so a member's own record is never
// a stray. Every other name at a root still is, and so is a since that is
// not a regular file.
func TestRootShapePermitsSince(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	peer := cfg.Others()[0]
	for _, store := range []string{cfg.Identity, peer} {
		for _, name := range []string{"since", "since.tmp"} {
			if err := os.WriteFile(filepath.Join(tmp, "stores", store, name), []byte("2026-09-21T11:00:00Z\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []string{cfg.Identity, peer} {
		for _, name := range []string{"since", "since.tmp"} {
			sub := store + "/" + name
			if hasFinding(out, "S1", sub) || hasFinding(out, "I6", sub) || hasFinding(out, "S2", sub) {
				t.Errorf("%s reported as a stray: %v", sub, out.Failing)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "stores", cfg.Identity, "sincere"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(tmp, "stores", peer, "since")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tmp, "stores", peer, "since"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(out, "S1", cfg.Identity+"/sincere") {
		t.Errorf("an unknown name at the own root not reported: %v", out.Failing)
	}
	if !hasFinding(out, "S2", peer+"/since") {
		t.Errorf("a since that is a directory not reported: %v", out.Failing)
	}
}

// observing-since is a check about this observer's own store, run in every
// cycle and listed in every heartbeat. On a real disk it fails when the own
// store does not record when this observer began, or records it unreadably,
// and passes on a well-formed record; its failure belongs in the fault file
// (SPEC 3.3), because only its owner can mend it.
func TestObservingSinceCheck(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	cfg.DryRun = false
	own := filepath.Join(tmp, "stores", cfg.Identity)
	p := filepath.Join(own, "since")
	run := func() *Outcome {
		t.Helper()
		st.ObservingSince = readObservingSince(own)
		out, err := RunCycle(cfg, st)
		if err != nil {
			t.Fatal(err)
		}
		listed := false
		for _, c := range out.Publish.Checks {
			if c == "observing-since" {
				listed = true
			}
		}
		if !listed {
			t.Errorf("observing-since not listed among the checks: %v", out.Publish.Checks)
		}
		return out
	}
	inFault := func(out *Outcome) bool {
		for _, f := range out.Fault.Local {
			if f.Check == "observing-since" {
				return true
			}
		}
		return false
	}

	out := run()
	if !hasFinding(out, "observing-since", "") {
		t.Errorf("a missing record not reported: %v", out.Failing)
	}
	if !inFault(out) {
		t.Errorf("a missing record is not carried by the fault: %+v", out.Fault)
	}

	if err := os.WriteFile(p, []byte("2026-02-30T00:00:00Z\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out = run(); !hasFinding(out, "observing-since", "") {
		t.Errorf("a record that does not round-trip not reported: %v", out.Failing)
	}

	if err := os.WriteFile(p, []byte("2026-09-20T10:07:25Z"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out = run(); !hasFinding(out, "observing-since", "") {
		t.Errorf("a record without its line feed not reported: %v", out.Failing)
	}

	if err := os.WriteFile(p, []byte(formatTimestamp(cfg.Now.Add(-time.Hour))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out = run(); hasFinding(out, "observing-since", "") {
		t.Errorf("a well-formed record reported: %v", out.Failing)
	} else if inFault(out) {
		t.Errorf("a well-formed record carried by the fault: %+v", out.Fault)
	}
}

// A since deleted while the observer runs is noticed by the next cycle, not
// the next start: the real-disk driver re-reads <own>/since before every
// cycle, so observing-since fails on the cycle after the deletion and is
// carried in the fault that cycle publishes. Read once on start, the value
// would outlive the record it stands for.
func TestObservingSinceRereadEachCycle(t *testing.T) {
	cfg, _, tmp := fixtureCopy(t, "healthy-ring")
	cfg.DryRun = false
	own := filepath.Join(tmp, "stores", cfg.Identity)
	st, err := startUp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.ObservingSince == nil {
		t.Fatal("the first start did not record since")
	}
	if err := os.Remove(filepath.Join(own, "since")); err != nil {
		t.Fatal(err)
	}
	// One cycle of the real driver, stopping after it.
	if err := run(cfg, st, 0, 1, nil); err != nil {
		t.Fatal(err)
	}
	if st.ObservingSince != nil {
		t.Errorf("state still carries %v after since was deleted", st.ObservingSince)
	}
	b, err := os.ReadFile(filepath.Join(own, "fault"))
	if err != nil {
		t.Fatalf("the cycle after since was deleted published no fault: %v", err)
	}
	f, err := parseFault(b)
	if err != nil {
		t.Fatalf("published fault does not parse: %v", err)
	}
	carried := false
	for _, x := range f.Failing {
		if x.Check == "observing-since" && x.Subject == "" {
			carried = true
		}
	}
	if !carried {
		t.Errorf("the fault does not carry observing-since: %+v", f.Failing)
	}
}

// A dry run must not touch the tree; the fixture harness checks this per
// fixture, and this guards the flag itself.
func TestDryRunWritesNothing(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	before := treeDiff(t, tmp, tmp, nil)
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	if after := treeDiff(t, tmp, tmp, nil); len(after) != len(before) {
		t.Errorf("tree changed: %v", after)
	}
	if _, err := os.Stat(filepath.Join(tmp, "stores", "tunnel", "heartbeat", "0000000045.hb")); err == nil {
		t.Error("heartbeat 45 was written during a dry run")
	}
}

// SPEC 6 at the deployment's window of 3: the owner keeps the three most
// recent entries, a reader finds its record while it is at most two cycles
// old, and a record three cycles old is outside the chain (V7, I1). The
// folder may hold WINDOW + 1 entries between the publish and the prune,
// and no more (C2).
func TestWindowThree(t *testing.T) {
	adminHash := func(t *testing.T, tmp string, seq int64) *string {
		h := hashFile(t, hbPath(tmp, "admin", seq, "heartbeat"))
		return &h
	}
	pruned := func(t *testing.T, tmp string) {
		for _, dir := range [][]string{{"admin", "heartbeat"}, {"material", "copy", "heartbeat"}, {"super", "copy-admin", "heartbeat"}} {
			d := filepath.Join(append([]string{tmp, "stores"}, dir...)...)
			prune(d, 44, 3, nil, "")
			if names := listHeartbeats(t, d); strings.Join(names, ",") != "0000000042.hb,0000000043.hb,0000000044.hb" {
				t.Fatalf("%s pruned at window 3 to %v", d, names)
			}
		}
	}
	// A record two cycles old (42, with 44 current): in the window, alive.
	cfg, st, tmp := fixtureCopy(t, "chain-ancestor-in-window")
	cfg.Window = 3
	pruned(t, tmp)
	st.Basis["admin"] = adminHash(t, tmp, 42)
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdicts["admin"] != VerdictAlive || hasFinding(out, "I1", "admin") {
		t.Fatalf("a record two cycles old at window 3: admin %v, failing %v", out.Verdicts["admin"], out.Failing)
	}
	// A record three cycles old (41): pruned at window 3, so I1.
	cfg, st, tmp = fixtureCopy(t, "chain-ancestor-in-window")
	cfg.Window = 3
	st.Basis["admin"] = adminHash(t, tmp, 41)
	pruned(t, tmp)
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if out.Verdicts["admin"] != VerdictUnknown || !hasFinding(out, "I1", "admin") {
		t.Fatalf("a record three cycles old at window 3: admin %v, failing %v", out.Verdicts["admin"], out.Failing)
	}
	// Unpruned, 41 to 44 is WINDOW + 1 at window 3: the transient between
	// publish and prune, no S3; a fifth entry is S3.
	cfg, st, _ = fixtureCopy(t, "chain-ancestor-in-window")
	cfg.Window = 3
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(out, "S3", "admin/heartbeat") {
		t.Fatalf("WINDOW + 1 entries at window 3 fired S3: %v", out.Failing)
	}
	cfg, st, tmp = fixtureCopy(t, "chain-ancestor-in-window")
	cfg.Window = 3
	if err := os.WriteFile(hbPath(tmp, "admin", 40, "heartbeat"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(out, "S3", "admin/heartbeat") {
		t.Fatalf("WINDOW + 2 entries at window 3 fired no S3: %v", out.Failing)
	}
}

// declaredLocal is local checks that declare two identifiers and fail
// with one of them and with a ring identifier.
type declaredLocal struct{}

func (declaredLocal) Identifiers() []string     { return []string{"local-a", "local-b"} }
func (declaredLocal) RingIdentifiers() []string { return []string{"ring-x"} }
func (declaredLocal) Run(*Config, *State, map[string]PeerView) []Finding {
	return []Finding{{Check: "local-b", Subject: "s"}, {Check: "ring-x", Subject: "admin"}}
}

// SPEC 3.3: the fault carries the structural local checks and every
// identifier the member's local checks declare, and nothing about another
// member. The set is built once for the cycle (localSet).
func TestFaultCarriesTheDeclaredLocalChecks(t *testing.T) {
	cfg, st, _ := fixtureCopy(t, "healthy-ring")
	cfg.Local = declaredLocal{}
	set := localSet(cfg)
	for id := range structuralLocal {
		if !set[id] {
			t.Fatalf("%s is structural and local, and not in the set", id)
		}
	}
	if !set["local-a"] || !set["local-b"] || set["ring-x"] || set["I1"] || len(set) != len(structuralLocal)+2 {
		t.Fatalf("the local set is %v", set)
	}
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Fault.Local) != 1 || out.Fault.Local[0] != (Finding{Check: "local-b", Subject: "s"}) {
		t.Fatalf("the fault carries %v, want the one declared local finding", out.Fault.Local)
	}
}
