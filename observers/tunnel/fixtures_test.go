package main

// fixtures_test.go drives one cycle of the observer against every fixture in
// the ring's own oracle (observers/testdata, described by its FIXTURES.md)
// and judges the outcome as that document says: verdicts exact per member,
// the failing set as a set, the halt's reason and subject, the publish fields
// present in the manifest, the relay decision and the ordered clears list.
//
// The implementation never writes into the tree: RunCycle reports what it
// would write. Each fixture is copied into a temp dir so that a defect that
// did write would be visible as a diff rather than as damage to the oracle.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixturesRoot is where the oracle lives: observers/testdata/fixtures,
// relative to this package directory, which is where go test runs.
// OBSERVER_FIXTURES overrides it.
const fixturesRoot = `../testdata/fixtures`

// The ring the fixtures describe, which is this ring. Membership is declared
// (SPEC 4), so the harness declares it rather than listing the tree; the
// members themselves come from each manifest's directories. The copy cycle
// is SPEC 2: material writes tunnel/copy, tunnel writes admin/copy, admin
// writes material/copy; super writes copy-super/ in each of the three
// (observers/README).
var (
	fixtureCoordinator = "super"
	fixtureCopyAuthor  = map[string]string{"tunnel": "material", "admin": "tunnel", "material": "admin"}
)

// fixtureSubtrees are the subtrees a fixture may carry (FIXTURES.md):
// stores/ for /stores/, traces/ for the schedule traces, gt/ for the
// proxy's own trace, which the segment and substance fixtures carry and
// expect.trace judges, and material/ for the files the proxy's start line
// names by a path relative to the fixture root, which expect.surface
// judges the substance rules over. Each is copied as it is and diffed
// after the cycle.
var fixtureSubtrees = []string{"stores", "traces", "gt", "material"}

type manifest struct {
	Fixture      string             `json:"fixture"`
	Description  string             `json:"description"`
	Reader       string             `json:"reader"`
	ReaderBooted bool               `json:"reader_booted"`
	Parameters   manifestParams     `json:"parameters"`
	Directories  []string           `json:"directories"`
	Memory       map[string]string  `json:"memory"`
	Mtimes       map[string]string  `json:"mtimes"`
	Unchanged    map[string]float64 `json:"unchanged"`
	Traces       []manifestTrace    `json:"traces"`
	DB           map[string]int64   `json:"db"`
	// ObservingSince, when declared, is when the reader began observing;
	// absent, the harness supplies a year before now (see below).
	ObservingSince string                     `json:"observing_since"`
	Expect         map[string]json.RawMessage `json:"expect"`
}

type manifestParams struct {
	Window                   int     `json:"window"`
	StaleSlackCycles         float64 `json:"stale_slack_cycles"`
	StagingStaleAfterSeconds float64 `json:"staging_stale_after_seconds"`
	MaxHeartbeatBytes        int64   `json:"max_heartbeat_bytes"`
	MaxFaultBytes            int64   `json:"max_fault_bytes"`
	MaxHaltBytes             int64   `json:"max_halt_bytes"`
	// HeartbeatMaxAgeSeconds is V4b's limit; absent or 0, V4b is not
	// evaluated.
	HeartbeatMaxAgeSeconds float64 `json:"heartbeat_max_age_seconds"`
	// SlotOwners is the member-to-account mapping of H7; absent, the
	// owner clause of procedure H is not evaluated, which is how every
	// fixture reads: a fixture tree carries no ownership, so no fixture
	// sets it, and the clause is proved in each member's own suite.
	SlotOwners map[string]string `json:"slot_owners"`
	Now        string            `json:"now"`
}

type manifestTrace struct {
	Schedule        string   `json:"schedule"`
	PeriodSeconds   float64  `json:"period_seconds"`
	MarginSeconds   float64  `json:"margin_seconds"`
	DeadlineSeconds float64  `json:"deadline_seconds"`
	Declared        []string `json:"declared"`
}

type expectFinding struct {
	Check   string  `json:"check"`
	Subject *string `json:"subject"`
}

type expectHalt struct {
	Writes  bool    `json:"writes"`
	Reason  string  `json:"reason"`
	Subject *string `json:"subject"`
}

type expectRelay struct {
	Writes         []string `json:"writes"`
	Leaves         []string `json:"leaves"`
	BytesOf        string   `json:"bytes_of"`
	OwnHaltWritten *bool    `json:"own_halt_written"`
}

// fixtureRoot is where the oracle is read from: fixturesRoot, or the
// OBSERVER_FIXTURES override.
func fixtureRoot() string {
	if v := os.Getenv("OBSERVER_FIXTURES"); v != "" {
		return v
	}
	return fixturesRoot
}

// readManifest reads one fixture's manifest.json.
func readManifest(tb testing.TB, dir string) *manifest {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		tb.Fatalf("manifest: %v", err)
	}
	m := new(manifest)
	if err := json.Unmarshal(raw, m); err != nil {
		tb.Fatalf("manifest: %v", err)
	}
	return m
}

// recreateFixture recreates the fixture at dir under a fresh temp dir,
// the way step 1 of the harness does, and returns its manifest and that
// dir. It is the one way a test copies a fixture: every test helper that
// wants a fixture tree goes through it, never through copyTree alone.
//
// The directories come first and from the manifest, not from the oracle
// on disk, because git stores no empty directory: on a fresh checkout
// every empty one is absent (a healthy member's halts/ among them), so a
// copy of the files alone hands the observer a ring whose halts/ cannot
// be listed (procedure H, H1) and whose halt slots cannot be written.
// The oracle carries no placeholder files instead, since a file in halts/
// would change what the fixture says. Then the files of stores/ and
// traces/ with their mtimes, then the mtimes the manifest sets.
func recreateFixture(tb testing.TB, dir string) (*manifest, string) {
	tb.Helper()
	m := readManifest(tb, dir)
	tmp := tb.TempDir()
	for _, d := range m.Directories {
		if err := os.MkdirAll(filepath.Join(tmp, filepath.FromSlash(d)), 0o755); err != nil {
			tb.Fatal(err)
		}
	}
	for _, sub := range fixtureSubtrees {
		src := filepath.Join(dir, sub)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyTree(src, filepath.Join(tmp, sub)); err != nil {
			tb.Fatalf("copy %s: %v", sub, err)
		}
	}
	for rel, ts := range m.Mtimes {
		when, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			tb.Fatalf("mtime %s: %v", rel, err)
		}
		p := filepath.Join(tmp, filepath.FromSlash(rel))
		if err := os.Chtimes(p, when, when); err != nil {
			tb.Fatalf("chtimes %s: %v", rel, err)
		}
	}
	return m, tmp
}

// TestFixtureCopiesCarryManifestDirectories guards what the unit tests
// rest on: a fixture copied by a test helper carries every directory its
// manifest lists, on any checkout. It fails on the checkout where a helper
// would silently miss one. It also reports, for the oracle as checked out,
// how many manifest-listed directories are absent on disk: non-zero on a
// fresh clone (git stores no empty directory), zero on the tree that wrote
// the oracle. The helpers must be right on both, so the count is shown
// rather than assumed.
func TestFixtureCopiesCarryManifestDirectories(t *testing.T) {
	m := readManifest(t, filepath.Join(fixtureRoot(), "healthy-ring"))
	if len(m.Directories) == 0 {
		t.Fatal("healthy-ring manifest lists no directories")
	}
	_, _, viaFixtureCopy := fixtureCopy(t, "healthy-ring")
	benchCfg, _ := benchRing(t, 300, NoLocalChecks{})
	copies := map[string]string{
		"fixtureCopy": viaFixtureCopy,
		"benchRing":   filepath.Dir(benchCfg.StoresRoot),
	}
	for helper, tmp := range copies {
		for _, d := range m.Directories {
			info, err := os.Stat(filepath.Join(tmp, filepath.FromSlash(d)))
			if err != nil || !info.IsDir() {
				t.Errorf("%s: manifest directory %s is missing from the copy: %v", helper, d, err)
			}
		}
	}

	// The oracle as checked out.
	entries, err := os.ReadDir(fixtureRoot())
	if err != nil {
		t.Fatalf("fixture set not present at %s: %v", fixtureRoot(), err)
	}
	listed, absent, fixtures := 0, 0, 0
	example := ""
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fixtures++
		dir := filepath.Join(fixtureRoot(), e.Name())
		for _, d := range readManifest(t, dir).Directories {
			listed++
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(d))); err != nil {
				absent++
				if example == "" {
					example = e.Name() + "/" + d
				}
			}
		}
	}
	if fixtures == 0 {
		t.Fatalf("no fixtures under %s", fixtureRoot())
	}
	if absent == 0 {
		t.Logf("oracle as checked out: 0 of %d manifest-listed directories across %d fixtures absent on disk (the tree that wrote the oracle; a fresh clone would show a non-zero count)", listed, fixtures)
	} else {
		t.Logf("oracle as checked out: %d of %d manifest-listed directories across %d fixtures absent on disk (a fresh clone; first: %s); the copies above carried them all", absent, listed, fixtures, example)
	}
}

func TestFixtures(t *testing.T) {
	root := fixtureRoot()
	// The oracle is part of this repository, so its absence is a broken
	// checkout, not a missing optional dependency: fail, never skip.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("fixture set not present at %s: %v", root, err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n++
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			runFixture(t, filepath.Join(root, name))
		})
	}
	if n == 0 {
		t.Fatalf("no fixtures under %s", root)
	}
}

func runFixture(t *testing.T, dir string) {
	// 1. Recreate the tree: directories (empty ones matter), files, mtimes.
	m, tmp := recreateFixture(t, dir)

	// 2. Configure: identity, declared membership, parameters, traces, db.
	now, err := time.Parse(time.RFC3339, m.Parameters.Now)
	if err != nil {
		t.Fatalf("now: %v", err)
	}
	members := storeRoots(m.Directories)
	cfg := &Config{
		Identity:          m.Reader,
		Members:           members,
		Coordinator:       fixtureCoordinator,
		CopyAuthor:        fixtureCopyAuthor,
		StoresRoot:        filepath.Join(tmp, "stores"),
		TracesRoot:        filepath.Join(tmp, "traces"),
		Window:            m.Parameters.Window,
		StaleSlack:        m.Parameters.StaleSlackCycles,
		StagingStaleAfter: secs(m.Parameters.StagingStaleAfterSeconds),
		MaxHeartbeatBytes: m.Parameters.MaxHeartbeatBytes,
		MaxFaultBytes:     m.Parameters.MaxFaultBytes,
		MaxHaltBytes:      m.Parameters.MaxHaltBytes,
		HeartbeatMaxAge:   secs(m.Parameters.HeartbeatMaxAgeSeconds), // V4b: evaluated only where a fixture sets it
		SlotOwners:        m.Parameters.SlotOwners,                   // H7: likewise; nil in every fixture
		CadenceSeconds:    10,
		Now:               now,
		DB:                m.DB,
		Local:             NoLocalChecks{},
		DryRun:            true,
	}
	for _, tr := range m.Traces {
		cfg.Traces = append(cfg.Traces, TraceSchedule{
			Schedule: tr.Schedule,
			Period:   secs(tr.PeriodSeconds),
			Margin:   secs(tr.MarginSeconds),
			Deadline: secs(tr.DeadlineSeconds),
			Declared: tr.Declared,
		})
	}

	// 3. In-process state as reader_booted describes (FIXTURES.md, SPEC 7).
	st := &State{Started: now, Memory: map[string]string{}, Unchanged: map[string]time.Duration{}}
	ownHB := filepath.Join(cfg.StoresRoot, m.Reader, "heartbeat")
	hbEntries := listHeartbeats(t, ownHB)
	for _, name := range hbEntries {
		rel := path.Join(m.Reader, "heartbeat", name)
		st.Memory[rel] = hashFile(t, filepath.Join(ownHB, name))
	}
	for _, f := range []string{"fault", "halt"} {
		p := filepath.Join(cfg.StoresRoot, m.Reader, f)
		if _, err := os.Stat(p); err == nil {
			st.Memory[path.Join(m.Reader, f)] = hashFile(t, p)
		}
	}
	if m.ReaderBooted {
		st.HasBasis = false
	} else {
		// Slots in the other stores' halts/ are the reader's own writes too.
		for _, other := range cfg.Others() {
			p := filepath.Join(cfg.StoresRoot, other, "halts", m.Reader)
			if _, err := os.Stat(p); err == nil {
				st.Memory[path.Join(other, "halts", m.Reader)] = hashFile(t, p)
			}
		}
		// Basis: what the reader's previous cycle wrote, its highest heartbeat.
		if len(hbEntries) > 0 {
			b, err := os.ReadFile(filepath.Join(ownHB, hbEntries[len(hbEntries)-1]))
			if err != nil {
				t.Fatal(err)
			}
			hb, err := parseHeartbeat(b, members)
			if err != nil {
				t.Fatalf("reader's own highest heartbeat does not parse: %v", err)
			}
			st.HasBasis = true
			st.Basis = hb.Observed
		}
	}
	if m.Memory != nil {
		st.Memory = map[string]string{}
		for k, v := range m.Memory {
			st.Memory[strings.TrimPrefix(k, "stores/")] = v
		}
	}
	for k, v := range m.Unchanged {
		st.Unchanged[k] = secs(v)
	}

	// When this reader began observing, which T1 consults to ask whether a
	// schedule has had time to run at all. main.go reads it from <own>/since;
	// a fixture is a read-only snapshot whose store carries no such file, so
	// the harness supplies it here with the rest of the in-process state.
	//
	// The default is a year before the fixture's now, so a schedule that has
	// never run is overdue, which is what these fixtures expect. A fixture
	// that wants the other branch, where nothing is due yet, declares its
	// own observing_since.
	since := now.Add(-365 * 24 * time.Hour)
	if m.ObservingSince != "" {
		if since, err = parseTimestamp(m.ObservingSince); err != nil {
			t.Fatalf("observing_since: %v", err)
		}
	}
	st.ObservingSince = &since
	// The ownership of the own store, likewise: main.go probes it before
	// every cycle against the deployment's tree; a fixture tree carries no
	// ownership, so the harness supplies the probe satisfied.
	st.OwnStorePrivate = []string{}

	// 4. One cycle, dry-run.
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatalf("RunCycle: %v", err)
	}

	// Nothing may have been written into the tree.
	if changed := treeDiff(t, dir, tmp, m); len(changed) > 0 {
		t.Errorf("implementation wrote into the fixture tree: %v", changed)
	}

	// 5. Judge.
	judge(t, m, cfg, out)

	// 6. The proxy's trace, where the fixture carries one.
	judgeTrace(t, m, tmp)

	// 7. A surface over it, where the fixture expects one.
	judgeSurface(t, m, tmp, now)

	// 8. The boot that ended, where the fixture carries two boots.
	judgeBootEnded(t, m, tmp, now)
}

// expectTrace is what the reader must conclude of a fixture's gt/ tree,
// the proxy's own trace (FIXTURES.md): the boot judged, its record count,
// whether its last segment ends in a torn line, and the length of every
// segment's prefix of complete lines. By the segment rule (SPEC 14) each
// length is a length of content, the bytes before the first NUL, never a
// file size.
type expectTrace struct {
	Boot     int64            `json:"boot"`
	Records  int              `json:"records"`
	Torn     bool             `json:"torn"`
	Segments map[string]int64 `json:"segments"`
}

// judgeTrace reads the fixture's gt/ as the local checks read the proxy's
// trace (traceReadCurrent, every rule applied, the decode resumed from
// memory) twice over the same bytes, as two cycles over an unchanged
// trace do, and compares each read with expect.trace. The second read
// must leave trace-consistent nothing to report: a prefix that hashed one
// way must hash the same way again, whatever the file's size.
func judgeTrace(t *testing.T, m *manifest, tmp string) {
	raw, ok := m.Expect["trace"]
	if !ok {
		return
	}
	var want expectTrace
	mustUnmarshal(t, raw, &want)
	st := &State{}
	root := filepath.Join(tmp, "gt")
	for cycle := 1; cycle <= 2; cycle++ {
		boot, _, err := traceReadCurrent(st, root)
		if err != nil {
			t.Fatalf("trace read %d: %v", cycle, err)
		}
		if boot.Number != want.Boot || len(boot.Records) != want.Records || boot.Torn != want.Torn {
			t.Errorf("trace read %d: boot %d, %d records, torn %v; want boot %d, %d records, torn %v", cycle, boot.Number, len(boot.Records), boot.Torn, want.Boot, want.Records, want.Torn)
		}
		got := map[string]int64{}
		for _, seg := range boot.Segments {
			got[seg.Name] = int64(len(seg.Prefix))
		}
		if !reflect.DeepEqual(want.Segments, got) {
			t.Errorf("trace read %d: segment prefix lengths %v, want %v", cycle, got, want.Segments)
		}
		if f := traceConsistentFindings(st, boot); len(f) != 0 {
			t.Errorf("trace read %d: trace-consistent reported %v over an unchanged trace", cycle, f)
		}
	}
}

// expectSurface is what every member must compute of one surface's
// trace-only rules over a fixture's gt/ (FIXTURES.md): the owner (tunnel
// when absent, or admin), the complete set of findings, for the tunnel
// surface the two substance rules (SPEC 14.3, substance.go) among them,
// with the fixture's now, the material paths of the start line resolved
// against the fixture root (its material/), and the policy query the
// fixture assumes as the members' -policy-query.
type expectSurface struct {
	Owner       string          `json:"owner"`
	PolicyQuery string          `json:"policy_query"`
	Findings    []expectFinding `json:"findings"`
}

// judgeSurface reads the fixture's gt/ as the members do and computes the
// named surface as every member computes it for surface-disagree
// (surfaceFindings), twice over the same bytes with one memory, as two
// cycles do: the first judges every record, the second extends the first's
// kept judgement (judgememory.go) and judges the chains from the first's
// memory, and must find the same.
func judgeSurface(t *testing.T, m *manifest, tmp string, now time.Time) {
	raw, ok := m.Expect["surface"]
	if !ok {
		return
	}
	var want expectSurface
	mustUnmarshal(t, raw, &want)
	owner := want.Owner
	if owner == "" {
		owner = surfaceTunnel
	}
	if surfaceIdentifiers(owner) == nil {
		t.Fatalf("surface owner %q is not a surface", owner)
	}
	ws := make([]string, 0, len(want.Findings))
	for _, f := range want.Findings {
		ws = append(ws, findingKey(f.Check, f.Subject))
	}
	sort.Strings(ws)
	st := &State{}
	cfg := &Config{PolicyQuery: want.PolicyQuery, MaterialBase: tmp}
	root := filepath.Join(tmp, "gt")
	for cycle := 1; cycle <= 2; cycle++ {
		boot, _, err := traceReadCurrent(st, root)
		if err != nil {
			t.Fatalf("surface read %d: %v", cycle, err)
		}
		if len(boot.Records) == 0 || boot.Records[0].Start == nil {
			t.Fatalf("surface read %d: the boot has no start line", cycle)
		}
		var kept *tunnelState
		if st.TunnelJudgement != nil {
			kept = st.TunnelJudgement.tunnel
		}
		got := surfaceFindings(owner, boot, now, surfaceMargins{}, substanceJudgeFor(cfg, st))
		if owner == surfaceTunnel && cycle == 2 && (kept == nil || st.TunnelJudgement.tunnel != kept) {
			t.Errorf("surface read 2: the first read's judgement was not kept")
		}
		gs := make([]string, 0, len(got))
		for _, f := range got {
			gs = append(gs, findingKey(f.Check, f.SubjectPtr()))
		}
		sort.Strings(gs)
		if !reflect.DeepEqual(ws, gs) {
			t.Errorf("surface read %d: findings %v, want %v", cycle, gs, ws)
		}
	}
	if owner == surfaceTunnel && (st.Substance == nil || st.Substance.Boot == 0) {
		t.Errorf("no substance memory kept across the two reads")
	}
}

// expectBootEnded is what a member that read boot Previous last cycle
// must conclude of it now that a higher boot is current (FIXTURES.md,
// SPEC 14.3 boot-ended): the complete set of findings, found once.
type expectBootEnded struct {
	Previous int64           `json:"previous"`
	Findings []expectFinding `json:"findings"`
}

// judgeBootEnded gives the implementation the memory of having read boot
// previous last cycle, reads gt/ as its local checks do and compares what
// it concludes of the ended boot; then reads again with the same memory,
// as the next cycle does, and requires nothing, and once with no memory,
// as a member started after the restart, and requires nothing.
func judgeBootEnded(t *testing.T, m *manifest, tmp string, now time.Time) {
	raw, ok := m.Expect["boot_ended"]
	if !ok {
		return
	}
	var want expectBootEnded
	mustUnmarshal(t, raw, &want)
	ws := make([]string, 0, len(want.Findings))
	for _, f := range want.Findings {
		ws = append(ws, findingKey(f.Check, f.Subject))
	}
	sort.Strings(ws)
	root := filepath.Join(tmp, "gt")
	cycle := func(st *State) []string {
		boot, _, err := traceReadCurrent(st, root)
		if err != nil {
			t.Fatalf("boot-ended read: %v", err)
		}
		previous := st.TraceBoot
		traceConsistentFindings(st, boot)
		got := bootEndedFindings(st, root, previous, boot, now, 0)
		gs := make([]string, 0, len(got))
		for _, f := range got {
			gs = append(gs, findingKey(f.Check, f.SubjectPtr()))
		}
		sort.Strings(gs)
		return gs
	}
	st := &State{TraceBoot: want.Previous}
	if gs := cycle(st); !reflect.DeepEqual(ws, gs) {
		t.Errorf("boot-ended: findings %v, want %v", gs, ws)
	}
	if gs := cycle(st); len(gs) != 0 {
		t.Errorf("boot-ended judged the same boot twice: %v", gs)
	}
	if gs := cycle(&State{}); len(gs) != 0 {
		t.Errorf("boot-ended judged a boot this member never saw end: %v", gs)
	}
}

func judge(t *testing.T, m *manifest, cfg *Config, out *Outcome) {
	if raw, ok := m.Expect["verdicts"]; ok {
		var want map[string]string
		mustUnmarshal(t, raw, &want)
		got := map[string]string{}
		for k, v := range out.Verdicts {
			got[k] = string(v)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("verdicts: want %v, got %v", want, got)
		}
	}
	if raw, ok := m.Expect["failing"]; ok {
		var want []expectFinding
		mustUnmarshal(t, raw, &want)
		ws := make([]string, 0, len(want))
		for _, f := range want {
			ws = append(ws, findingKey(f.Check, f.Subject))
		}
		gs := make([]string, 0, len(out.Failing))
		for _, f := range out.Failing {
			gs = append(gs, findingKey(f.Check, f.SubjectPtr()))
		}
		sort.Strings(ws)
		sort.Strings(gs)
		if !reflect.DeepEqual(ws, gs) {
			t.Errorf("failing set: want %v, got %v", ws, gs)
		}
	}
	if raw, ok := m.Expect["halt_in_force_before"]; ok {
		var want bool
		mustUnmarshal(t, raw, &want)
		if want != out.HaltInForceBefore {
			t.Errorf("halt_in_force_before: want %v, got %v", want, out.HaltInForceBefore)
		}
	}
	if raw, ok := m.Expect["halt"]; ok {
		var want expectHalt
		mustUnmarshal(t, raw, &want)
		if want.Writes != out.Halt.Writes {
			t.Errorf("halt.writes: want %v, got %v", want.Writes, out.Halt.Writes)
		} else if want.Writes {
			if want.Reason != out.Halt.Reason || !ptrEq(want.Subject, out.Halt.SubjectPtr()) {
				t.Errorf("halt: want %s(%s), got %s(%s)", want.Reason, ptrStr(want.Subject), out.Halt.Reason, ptrStr(out.Halt.SubjectPtr()))
			}
		}
	}
	if raw, ok := m.Expect["publish"]; ok {
		var want map[string]json.RawMessage
		mustUnmarshal(t, raw, &want)
		if r, ok := want["sequence"]; ok {
			var seq int64
			mustUnmarshal(t, r, &seq)
			if seq != out.Publish.Sequence {
				t.Errorf("publish.sequence: want %d, got %d", seq, out.Publish.Sequence)
			}
		}
		if r, ok := want["previous"]; ok {
			var prev *string
			mustUnmarshal(t, r, &prev)
			if !ptrEq(prev, out.Publish.Previous) {
				t.Errorf("publish.previous: want %s, got %s", ptrStr(prev), ptrStr(out.Publish.Previous))
			}
		}
		if r, ok := want["observed"]; ok {
			var obs map[string]*string
			mustUnmarshal(t, r, &obs)
			if !reflect.DeepEqual(obs, out.Publish.Observed) {
				t.Errorf("publish.observed: want %s, got %s", fmtObserved(obs), fmtObserved(out.Publish.Observed))
			}
		}
		if r, ok := want["boot"]; ok {
			var boot *struct {
				ResumedFrom *int64 `json:"resumed_from"`
			}
			mustUnmarshal(t, r, &boot)
			switch {
			case boot == nil && out.Publish.Boot != nil:
				t.Errorf("publish.boot: want null, got %+v", out.Publish.Boot)
			case boot != nil && out.Publish.Boot == nil:
				t.Errorf("publish.boot: want %+v, got null", boot)
			case boot != nil && !int64PtrEq(boot.ResumedFrom, out.Publish.Boot.ResumedFrom):
				t.Errorf("publish.boot.resumed_from: want %v, got %v", boot.ResumedFrom, out.Publish.Boot.ResumedFrom)
			}
		}
		if r, ok := want["stop"]; ok {
			var stop bool
			mustUnmarshal(t, r, &stop)
			if stop != out.Publish.Stop {
				t.Errorf("publish.stop: want %v, got %v", stop, out.Publish.Stop)
			}
		}
		// Not judged by value, but the harness must check the count agrees.
		if int64(len(out.Publish.Checks)) != out.Publish.CheckCount {
			t.Errorf("publish.check_count %d != len(checks) %d", out.Publish.CheckCount, len(out.Publish.Checks))
		}
		// The published bytes must classify and parse as a heartbeat under 3.2.
		if b := out.Publish.Bytes; len(b) > 0 {
			if classify(b) != KindHeartbeat {
				t.Errorf("published heartbeat does not begin with the marker: %q", b[:min(len(b), 24)])
			}
			if _, err := parseHeartbeat(b, cfg.Members); err != nil {
				t.Errorf("published heartbeat does not parse strictly: %v", err)
			}
		}
	}
	if raw, ok := m.Expect["relay"]; ok {
		var want expectRelay
		mustUnmarshal(t, raw, &want)
		if !sameSet(want.Writes, out.Relay.Writes) {
			t.Errorf("relay.writes: want %v, got %v", want.Writes, out.Relay.Writes)
		}
		if want.Leaves != nil && !sameSet(want.Leaves, out.Relay.Leaves) {
			t.Errorf("relay.leaves: want %v, got %v", want.Leaves, out.Relay.Leaves)
		}
		if want.BytesOf != "" {
			b, err := os.ReadFile(filepath.Join(cfg.StoresRoot, "..", filepath.FromSlash(want.BytesOf)))
			if err != nil {
				t.Fatalf("relay.bytes_of: %v", err)
			}
			if string(b) != string(out.Relay.Bytes) {
				t.Errorf("relay bytes: want those of %s (%d bytes), got %d bytes from %q", want.BytesOf, len(b), len(out.Relay.Bytes), out.Relay.From)
			}
		}
		if want.OwnHaltWritten != nil && *want.OwnHaltWritten != out.Halt.OwnHaltWritten {
			t.Errorf("relay.own_halt_written: want %v, got %v", *want.OwnHaltWritten, out.Halt.OwnHaltWritten)
		}
	}
	if raw, ok := m.Expect["clears"]; ok {
		var asBool bool
		if err := json.Unmarshal(raw, &asBool); err == nil {
			if asBool {
				t.Fatalf("clears: unexpected true")
			}
			if out.Clears != nil {
				t.Errorf("clears: want false, got removes %v", out.Clears.Removes)
			}
		} else {
			var want struct {
				Removes []string `json:"removes"`
			}
			mustUnmarshal(t, raw, &want)
			if out.Clears == nil {
				t.Errorf("clears: want removes %v, got false", want.Removes)
			} else {
				got := make([]string, 0, len(out.Clears.Removes))
				for _, r := range out.Clears.Removes {
					got = append(got, "stores/"+r)
				}
				if want.Removes == nil {
					want.Removes = []string{}
				}
				if !reflect.DeepEqual(want.Removes, got) {
					t.Errorf("clears.removes: want %v, got %v", want.Removes, got)
				}
			}
		}
	}
}

// Cases FIXTURES.md says the set does not cover. They are recorded as skips
// so the suite states what it has not shown, rather than silently omitting it.
func TestNotCoveredByFixtures(t *testing.T) {
	cases := map[string]string{
		"V1-store-unlistable":         "a fixture cannot make a directory unreadable portably (FIXTURES.md); needs a permission-change test in this suite",
		"own-store-writable":          "the re-read after publish and atomic publication are about writing; the fixtures are read-only snapshots",
		"cycle-within-cadence":        "cycle timing is not a property of files",
		"local-checks":                "per-observer content added in step 8; identifiers are the observer's own",
		"T1-never-run-not-due":        "needs a fixture declaring its own observing_since and a schedule with no runs; TestTraceNeverRunGrace covers it on a fixture copy",
		"behaviour-across-cycles":     "each fixture is one cycle",
		"runtime-coupling-halt-paths": "step 10 and step 11 are outside the fixture set",
		"I8-slot-owner":               "a fixture tree carries no ownership, so no fixture sets slot_owners and H7 is not evaluated over the set; TestSlotOwnerInTheCycle covers it on this host",
	}
	for name, why := range cases {
		t.Run(name, func(t *testing.T) { t.Skip(why) })
	}
}

// ---- helpers ----

func secs(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

func storeRoots(dirs []string) []string {
	seen := map[string]bool{}
	for _, d := range dirs {
		parts := strings.Split(d, "/")
		if len(parts) >= 2 && parts[0] == "stores" {
			seen[parts[1]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func listHeartbeats(t *testing.T, dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if reHeartbeatName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func hashFile(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	})
}

// treeDiff lists paths under tmp whose presence or bytes differ from the
// fixture, so that a write into the tree is caught.
func treeDiff(t *testing.T, fixture, tmp string, m *manifest) []string {
	want := map[string]string{}
	for _, sub := range fixtureSubtrees {
		src := filepath.Join(fixture, sub)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(fixture, p)
			want[filepath.ToSlash(rel)] = hashFile(t, p)
			return nil
		})
	}
	got := map[string]string{}
	for _, sub := range fixtureSubtrees {
		src := filepath.Join(tmp, sub)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(tmp, p)
			got[filepath.ToSlash(rel)] = hashFile(t, p)
			return nil
		})
	}
	var diff []string
	for k, v := range want {
		if got[k] != v {
			diff = append(diff, k)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return diff
}

func mustUnmarshal(t *testing.T, raw json.RawMessage, v interface{}) {
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("expect: %v", err)
	}
}

func findingKey(check string, subject *string) string {
	if subject == nil {
		return check + "(null)"
	}
	return check + "(" + *subject + ")"
}

func ptrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func int64PtrEq(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func ptrStr(s *string) string {
	if s == nil {
		return "null"
	}
	return *s
}

func fmtObserved(m map[string]*string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + "=" + ptrStr(m[k]) + " ")
	}
	return sb.String()
}

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) == 0 && len(y) == 0 {
		return true
	}
	return reflect.DeepEqual(x, y)
}
