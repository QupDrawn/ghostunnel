package main

// Structural tests. Every tree here is synthetic, built in t.TempDir() from
// files written in the exact formats the members use, with real sha256
// hashes for `previous` and `observed`, so the edges and copies are exercised
// the way they would be against a live store and not against a stub.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// ---- building trees -------------------------------------------------------

type synthTree struct {
	t      *testing.T
	root   string
	hashes map[string][]string // per observer, hash of every beat written, in order
	bytes  map[string][]byte   // per observer, bytes of the newest beat
}

func newSynthTree(t *testing.T) *synthTree {
	t.Helper()
	root := t.TempDir()
	for _, m := range members {
		mustMkdir(t, filepath.Join(root, m, "heartbeat"))
		mustMkdir(t, filepath.Join(root, m, "halts"))
		if m == coordinator {
			for _, a := range structural {
				mustMkdir(t, filepath.Join(root, m, "copy-"+a, "heartbeat"))
			}
		} else {
			mustMkdir(t, filepath.Join(root, m, "copy", "heartbeat"))
			mustMkdir(t, filepath.Join(root, m, "copy-"+coordinator, "heartbeat"))
		}
	}
	return &synthTree{t: t, root: root, hashes: map[string][]string{}, bytes: map[string][]byte{}}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (tr *synthTree) put(rel string, data []byte) string {
	tr.t.Helper()
	full := filepath.Join(tr.root, filepath.FromSlash(rel))
	mustMkdir(tr.t, filepath.Dir(full))
	if err := os.WriteFile(full, data, 0o644); err != nil {
		tr.t.Fatal(err)
	}
	return sha(data)
}

func (tr *synthTree) remove(rel string) {
	tr.t.Helper()
	if err := os.RemoveAll(filepath.Join(tr.root, filepath.FromSlash(rel))); err != nil {
		tr.t.Fatal(err)
	}
}

type hbWire struct {
	Kind           string             `json:"kind"`
	Version        int                `json:"version"`
	Observer       string             `json:"observer"`
	Sequence       int64              `json:"sequence"`
	Timestamp      string             `json:"timestamp"`
	CadenceSeconds int64              `json:"cadence_seconds"`
	Checks         []string           `json:"checks"`
	CheckCount     int64              `json:"check_count"`
	Observed       map[string]*string `json:"observed"`
	Previous       *string            `json:"previous"`
	Boot           *bootWire          `json:"boot"`
	Stop           bool               `json:"stop"`
}

type bootWire struct {
	Started     string `json:"started"`
	ResumedFrom *int64 `json:"resumed_from"`
}

type hbSpec struct {
	observer string
	seq      int64
	ts       time.Time
	cadence  int64
	observed map[string]*string // missing entries are written as null
	previous *string
	boot     bool
	stop     bool
	checks   int64
}

func hbBytes(s hbSpec) []byte {
	obs := map[string]*string{}
	for _, m := range members {
		if m != s.observer {
			obs[m] = s.observed[m]
		}
	}
	checks := make([]string, 0, s.checks)
	for i := int64(0); i < s.checks; i++ {
		checks = append(checks, "check-"+string(rune('a'+i)))
	}
	w := hbWire{
		Kind: "heartbeat", Version: 1, Observer: s.observer, Sequence: s.seq,
		Timestamp: s.ts.UTC().Format(timestampLayout), CadenceSeconds: s.cadence,
		Checks: checks, CheckCount: s.checks, Observed: obs, Previous: s.previous, Stop: s.stop,
	}
	if s.boot {
		w.Boot = &bootWire{Started: s.ts.Add(-time.Minute).UTC().Format(timestampLayout)}
	}
	b, err := json.Marshal(w)
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// beat writes one heartbeat into the observer's own folder, chained to the
// one before it, and returns its hash.
func (tr *synthTree) beat(s hbSpec) string {
	tr.t.Helper()
	if s.cadence == 0 {
		s.cadence = 5
	}
	if s.ts.IsZero() {
		s.ts = fixedNow.Add(-time.Second)
	}
	if s.checks == 0 {
		s.checks = 7
	}
	if s.previous == nil {
		if prev := tr.hashes[s.observer]; len(prev) > 0 {
			p := prev[len(prev)-1]
			s.previous = &p
		}
	}
	b := hbBytes(s)
	h := tr.put(s.observer+"/heartbeat/"+heartbeatName(s.seq), b)
	tr.hashes[s.observer] = append(tr.hashes[s.observer], h)
	tr.bytes[s.observer] = b
	return h
}

// newestOfOthers is what a member would record as observed if it read every
// other member right now.
func (tr *synthTree) newestOfOthers(self string) map[string]*string {
	out := map[string]*string{}
	for _, m := range members {
		if m == self {
			continue
		}
		if hs := tr.hashes[m]; len(hs) > 0 {
			h := hs[len(hs)-1]
			out[m] = &h
		}
	}
	return out
}

// copyAll deposits every author's newest bytes into every copy location.
func (tr *synthTree) copyAll() {
	for _, m := range members {
		if m == coordinator {
			for _, a := range structural {
				tr.put(m+"/copy-"+a+"/heartbeat/"+heartbeatName(int64(len(tr.hashes[a]))), tr.bytes[a])
			}
			continue
		}
		a := copyAuthor[m]
		tr.put(m+"/copy/heartbeat/"+heartbeatName(int64(len(tr.hashes[a]))), tr.bytes[a])
		tr.put(m+"/copy-"+coordinator+"/heartbeat/"+heartbeatName(int64(len(tr.hashes[coordinator]))), tr.bytes[coordinator])
	}
}

func (tr *synthTree) since(m string, at time.Time) {
	tr.put(m+"/since", []byte(at.UTC().Format(timestampLayout)+"\n"))
}

// buildClearRing: three rounds of beats in display order, each beat
// observing whatever was newest when it was written, all copies matching,
// every since file present.
func buildClearRing(t *testing.T) *synthTree {
	tr := newSynthTree(t)
	for seq := int64(1); seq <= 3; seq++ {
		for _, m := range members {
			tr.beat(hbSpec{observer: m, seq: seq, observed: tr.newestOfOthers(m)})
		}
	}
	tr.copyAll()
	for _, m := range members {
		tr.since(m, fixedNow.Add(-2*time.Hour))
	}
	return tr
}

func faultBytes(observer string, failing ...[2]string) []byte {
	type finding struct {
		Check   string  `json:"check"`
		Subject *string `json:"subject"`
	}
	w := struct {
		Kind     string    `json:"kind"`
		Version  int       `json:"version"`
		Observer string    `json:"observer"`
		Failing  []finding `json:"failing"`
	}{Kind: "fault", Version: 1, Observer: observer, Failing: []finding{}}
	for _, f := range failing {
		var subj *string
		if f[1] != "" {
			s := f[1]
			subj = &s
		}
		w.Failing = append(w.Failing, finding{Check: f[0], Subject: subj})
	}
	b, _ := json.Marshal(w)
	return append(b, '\n')
}

func haltBytes(observer, reason, subject string, seq int64, when time.Time) []byte {
	var subj *string
	if subject != "" {
		subj = &subject
	}
	w := struct {
		Kind     string  `json:"kind"`
		Version  int     `json:"version"`
		Observer string  `json:"observer"`
		Reason   string  `json:"reason"`
		Subject  *string `json:"subject"`
		Sequence int64   `json:"sequence"`
		When     string  `json:"when"`
		Detail   string  `json:"detail"`
	}{Kind: "halt", Version: 1, Observer: observer, Reason: reason, Subject: subj, Sequence: seq,
		When: when.UTC().Format(timestampLayout), Detail: "synthetic"}
	b, _ := json.Marshal(w)
	return append(b, '\n')
}

// buildHaltedRing: a clear ring on which tunnel has found something, written
// fault and halt, and delivered the halt into everybody else's slot.
func buildHaltedRing(t *testing.T) *synthTree {
	tr := buildClearRing(t)
	tr.put("tunnel/fault", faultBytes("tunnel", [2]string{"heartbeat-fresh", "admin"}, [2]string{"copy-current", "material"}))
	halt := haltBytes("tunnel", "heartbeat-fresh", "admin", 3, fixedNow.Add(-90*time.Second))
	tr.put("tunnel/halt", halt)
	for _, m := range []string{"super", "admin", "material"} {
		tr.put(m+"/halts/tunnel", halt)
	}
	return tr
}

// ---- reading frames -------------------------------------------------------

func render(t *testing.T, tr *synthTree, rates map[string]*float64) []string {
	t.Helper()
	return renderLines(tr.root, rates, fixedNow, true)
}

func joined(lines []string) string { return strings.Join(lines, "\n") }

// firstLine returns the first line matching the pattern, failing the test
// when none does.
func firstLine(t *testing.T, lines []string, pattern string) string {
	t.Helper()
	re := regexp.MustCompile(pattern)
	for _, l := range lines {
		if re.MatchString(l) {
			return l
		}
	}
	t.Fatalf("no line matches %q in:\n%s", pattern, joined(lines))
	return ""
}

func noLine(t *testing.T, lines []string, pattern string) {
	t.Helper()
	re := regexp.MustCompile(pattern)
	for _, l := range lines {
		if re.MatchString(l) {
			t.Fatalf("unexpected line %q (matches %q) in:\n%s", l, pattern, joined(lines))
		}
	}
}

// memberRow is the members-table row for m: the one that carries an age or
// the no-heartbeat marker, which the edge grid and slot rows never do.
func memberRow(t *testing.T, lines []string, m string) string {
	t.Helper()
	return firstLine(t, lines, `^  `+m+`\s+(.*\d+s ago|no heartbeat)`)
}

// edgeRow returns the four cells of the edge grid row for reader.
func edgeRow(t *testing.T, lines []string, reader string) []string {
	t.Helper()
	l := firstLine(t, lines, `^  `+reader+`\s+.*·`)
	f := strings.Fields(l)
	if len(f) != 5 || f[0] != reader {
		t.Fatalf("edge row for %s has unexpected shape: %q", reader, l)
	}
	return f[1:]
}

func copyRow(t *testing.T, lines []string, label string) string {
	t.Helper()
	return firstLine(t, lines, `^\s+`+regexp.QuoteMeta(label)+`\s+from \w+\s+\S+$`)
}

func fptr(f float64) *float64 { return &f }

// ---- the arguments --------------------------------------------------------

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestOnceBeatsWatchRegardlessOfOrder(t *testing.T) {
	for _, args := range [][]string{
		{"--watch", "--once"},
		{"--once", "--watch"},
		{"--interval=3", "--once"},
		{"--once", "--interval=3"},
		{"-watch", "-once"},
	} {
		o, err := parseArgs(args, envOf(nil), true)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if o.watch || !o.once {
			t.Errorf("%v: watch=%v once=%v, want watch=false once=true", args, o.watch, o.once)
		}
	}
}

func TestDefaultsFollowTheTerminal(t *testing.T) {
	o, err := parseArgs(nil, envOf(nil), true)
	if err != nil || !o.watch {
		t.Errorf("terminal, no args: want watch, got %+v %v", o, err)
	}
	o, err = parseArgs(nil, envOf(nil), false)
	if err != nil || o.watch {
		t.Errorf("pipe, no args: want once, got %+v %v", o, err)
	}
	if o.stores != defaultStores {
		t.Errorf("default stores = %q, want %q", o.stores, defaultStores)
	}
	if o.interval != 1 {
		t.Errorf("default interval = %d, want 1", o.interval)
	}
	if o.noColor {
		t.Errorf("colour should be on without NO_COLOR")
	}
}

func TestIntervalImpliesWatchAndHasAFloor(t *testing.T) {
	o, err := parseArgs([]string{"--interval=0"}, envOf(nil), false)
	if err != nil || !o.watch || o.interval != 1 {
		t.Errorf("--interval=0 on a pipe: got %+v %v, want watch with interval 1", o, err)
	}
	o, err = parseArgs([]string{"--interval=7"}, envOf(nil), false)
	if err != nil || !o.watch || o.interval != 7 {
		t.Errorf("--interval=7: got %+v %v", o, err)
	}
	if _, err := parseArgs([]string{"--interval=soon"}, envOf(nil), false); err == nil {
		t.Errorf("--interval=soon should be refused")
	}
}

func TestStoresAndColourFromEnvironment(t *testing.T) {
	o, _ := parseArgs(nil, envOf(map[string]string{storesEnv: "/somewhere/copied", "NO_COLOR": ""}), true)
	if o.stores != "/somewhere/copied" {
		t.Errorf("stores from env = %q", o.stores)
	}
	if !o.noColor {
		t.Errorf("NO_COLOR set (even empty) should disable colour")
	}
	o, _ = parseArgs([]string{"-stores", "/flag/wins"}, envOf(map[string]string{storesEnv: "/env"}), true)
	if o.stores != "/flag/wins" {
		t.Errorf("flag should override env, got %q", o.stores)
	}
	o, _ = parseArgs([]string{"--no-color"}, envOf(nil), true)
	if !o.noColor {
		t.Errorf("--no-color ignored")
	}
	if _, err := parseArgs([]string{"--bogus"}, envOf(nil), true); err == nil {
		t.Errorf("unknown flag should be refused")
	}
}

// ---- painting and arithmetic ----------------------------------------------

func TestPadIgnoresEscapes(t *testing.T) {
	coloured := paint("abc", "red", false)
	if coloured == "abc" {
		t.Fatal("paint with colour on returned bare text")
	}
	got := pad(coloured, 8)
	if visibleWidth(got) != 8 {
		t.Errorf("visible width %d, want 8: %q", visibleWidth(got), got)
	}
	if !strings.HasSuffix(got, "     ") {
		t.Errorf("padding should follow the escape, got %q", got)
	}
	if pad("abcdefghij", 4) != "abcdefghij" {
		t.Errorf("pad must never truncate")
	}
	// Bytes, not runes: a middle dot is two.
	if got := pad("·", 10); got != "·        " {
		t.Errorf("pad counts bytes like the original: %q", got)
	}
	if paint("x", "red", true) != "x" {
		t.Errorf("paint with colour off must return the bare text")
	}
	if paint("x", "no-such-colour", false) != "\033[0mx\033[0m" {
		t.Errorf("unknown colour should reset rather than guess")
	}
}

func TestDuration(t *testing.T) {
	cases := map[int64]string{0: "0s", 59: "59s", 60: "1m 0s", 90: "1m 30s", 3600: "1h 0m", 5400: "1h 30m", 86400: "1d 0h", 90000: "1d 1h"}
	for in, want := range cases {
		if got := duration(in); got != want {
			t.Errorf("duration(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestRatesBetween(t *testing.T) {
	ten, twenty := int64(10), int64(20)
	before := map[string]*int64{"super": &ten, "tunnel": &twenty, "admin": &ten, "material": nil}
	after := map[string]*int64{"super": &twenty, "tunnel": &ten, "admin": &ten, "material": &ten}
	r := ratesBetween(before, after, 5.0)
	if r["super"] == nil || *r["super"] != 0.5 {
		t.Errorf("super: 10 cycles in 5s should be 0.5 s/cycle, got %v", r["super"])
	}
	if r["tunnel"] != nil {
		t.Errorf("tunnel: sequence went backwards, want nil")
	}
	if r["admin"] != nil {
		t.Errorf("admin: no progress, want nil")
	}
	if r["material"] != nil {
		t.Errorf("material: no first sample, want nil")
	}
	if r := ratesBetween(before, after, 0); r["super"] != nil {
		t.Errorf("zero elapsed must give nil, not a division")
	}
}

func TestCycleCellAgainstTheCeiling(t *testing.T) {
	const cadence = 5
	if got := cycleCell(nil, cadence, true); got != "--/5s" {
		t.Errorf("no rate: %q", got)
	}
	if got := cycleCell(fptr(0.3), cadence, true); got != "0.3s/5s" {
		t.Errorf("plain: %q", got)
	}
	green := cycleCell(fptr(3.4), cadence, false)
	amber := cycleCell(fptr(3.6), cadence, false)
	red := cycleCell(fptr(5.0), cadence, false)
	if !strings.HasPrefix(green, "\033[0;32m") {
		t.Errorf("under 70%% of the cadence should be green: %q", green)
	}
	if !strings.HasPrefix(amber, "\033[0;33m") {
		t.Errorf("over 70%% should be amber: %q", amber)
	}
	if !strings.HasPrefix(red, "\033[1;31m") {
		t.Errorf("at the cadence should be red: %q", red)
	}
}

func TestAgeColour(t *testing.T) {
	if ageColour(11, 5) != "amber" || ageColour(12, 5) != "amber" {
		t.Errorf("past two cadences should be amber")
	}
	if ageColour(31, 5) != "red" {
		t.Errorf("past six cadences should be red")
	}
	if ageColour(10, 5) != "green" || ageColour(1000, 0) != "green" {
		t.Errorf("inside the window, or with no cadence to measure against, should be green")
	}
}

// ---- the since file -------------------------------------------------------

func TestObservingSince(t *testing.T) {
	tr := newSynthTree(t)
	tr.put("super/since", []byte("2026-09-25T10:00:00Z\n"))
	tr.put("tunnel/since", []byte("yesterday\n"))
	tr.put("admin/since", []byte("2026-02-30T00:00:00Z\n"))  // not a date
	tr.put("material/since", []byte("2026-09-25T10:00:00Z")) // no line feed
	if got := observingSince(filepath.Join(tr.root, "super")); got == nil || !got.Equal(time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("valid since: got %v", got)
	}
	for _, m := range []string{"tunnel", "admin", "material"} {
		if got := observingSince(filepath.Join(tr.root, m)); got != nil {
			t.Errorf("%s: want nil for a malformed since, got %v", m, got)
		}
	}
	if got := observingSince(filepath.Join(tr.root, "nowhere")); got != nil {
		t.Errorf("absent: want nil, got %v", got)
	}
	tr.put("super/since", []byte("2026-09-25T10:00:00Z\n\n"))
	if got := observingSince(filepath.Join(tr.root, "super")); got != nil {
		t.Errorf("two line feeds: want nil, got %v", got)
	}
}

// ---- whole frames ---------------------------------------------------------

func TestClearRing(t *testing.T) {
	tr := buildClearRing(t)
	rates := map[string]*float64{"super": fptr(0.3), "tunnel": fptr(0.4), "admin": nil, "material": fptr(4.0)}
	lines := render(t, tr, rates)

	firstLine(t, lines, `RING CLEAR .*4 members · 12 directed edges · nothing halted`)
	noLine(t, lines, `RING HALTED|RING INCOMPLETE|HALT SLOTS`)

	firstLine(t, lines, `^  MEMBER\s+STATE\s+SEQUENCE\s+LAST BEAT\s+CYCLE\s+OBSERVING\s+CHECKS$`)
	for i, m := range members {
		row := memberRow(t, lines, m)
		want := `^  ` + m + `\s+clear\s+3\s+1s ago\s+(0.[34]s|4.0s|--)/5s\s+2h 0m\s+7$`
		if !regexp.MustCompile(want).MatchString(row) {
			t.Errorf("row %d %q does not match %q", i, row, want)
		}
	}
	// The coordinator leads.
	if !strings.HasPrefix(memberRow(t, lines, "super"), "  super") || !strings.Contains(memberRow(t, lines, "material"), "4.0s/5s") {
		t.Errorf("rows: %s", joined(lines))
	}
	if idxOf(lines, `^  super\s+clear`) > idxOf(lines, `^  tunnel\s+clear`) {
		t.Errorf("super must be listed first")
	}

	// Beats were written in display order, so each reader saw the newest of
	// everybody written before it and the previous of everybody after.
	wantEdges := map[string][]string{
		"super":    {"·", "-1", "-1", "-1"},
		"tunnel":   {"ok", "·", "-1", "-1"},
		"admin":    {"ok", "ok", "·", "-1"},
		"material": {"ok", "ok", "ok", "·"},
	}
	for reader, want := range wantEdges {
		if got := edgeRow(t, lines, reader); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("edges %s: got %v want %v", reader, got, want)
		}
	}
	firstLine(t, lines, `^\s+ok\s+read the newest one$`)
	firstLine(t, lines, `^\s+past\s+read something so old`)

	firstLine(t, lines, `^  COPIES\s+all 9 match`)
	for _, label := range []string{"super/copy-tunnel", "super/copy-admin", "super/copy-material", "tunnel/copy", "tunnel/copy-super", "admin/copy", "admin/copy-super", "material/copy", "material/copy-super"} {
		if row := copyRow(t, lines, label); !strings.HasSuffix(row, " ok") {
			t.Errorf("copy %s: %q", label, row)
		}
	}
	if !strings.Contains(copyRow(t, lines, "tunnel/copy"), "from material") {
		t.Errorf("tunnel/copy is authored by material")
	}
	if !strings.Contains(copyRow(t, lines, "admin/copy"), "from tunnel") || !strings.Contains(copyRow(t, lines, "material/copy"), "from admin") {
		t.Errorf("copy cycle wrong: %s", joined(lines))
	}
	firstLine(t, lines, `GHOSTUNNEL.*observer ring.*2026-09-25T12:00:00Z`)
	if strings.Contains(joined(lines), "\033[") {
		t.Errorf("no-colour frame carries escapes")
	}
}

func idxOf(lines []string, pattern string) int {
	re := regexp.MustCompile(pattern)
	for i, l := range lines {
		if re.MatchString(l) {
			return i
		}
	}
	return -1
}

func TestHaltedRing(t *testing.T) {
	tr := buildHaltedRing(t)
	lines := render(t, tr, nil)

	firstLine(t, lines, `^\s+RING HALTED\s+heartbeat-fresh on admin, found by tunnel, 1m 30s ago$`)
	firstLine(t, lines, `^  4 of 4 members stopped\. Clearing is unanimous, so the work stays stopped until every member reads clean\.$`)
	noLine(t, lines, `RING CLEAR|RING INCOMPLETE`)

	if row := memberRow(t, lines, "tunnel"); !regexp.MustCompile(`^  tunnel\s+fault\s+3\s+`).MatchString(row) {
		t.Errorf("raiser should read fault: %q", row)
	}
	firstLine(t, lines, `^\s+failing: heartbeat-fresh:admin, copy-current:material$`)
	for _, m := range []string{"super", "admin", "material"} {
		if row := memberRow(t, lines, m); !regexp.MustCompile(`^  ` + m + `\s+halt\s+3\s+`).MatchString(row) {
			t.Errorf("%s carries a delivered slot and should read halt: %q", m, row)
		}
	}

	i := idxOf(lines, `^  HALT SLOTS`)
	if i < 0 {
		t.Fatalf("HALT SLOTS section missing:\n%s", joined(lines))
	}
	rest := lines[i:]
	firstLine(t, rest, `^  super\s+from tunnel$`)
	firstLine(t, rest, `^  admin\s+from tunnel$`)
	firstLine(t, rest, `^  material\s+from tunnel$`)
	firstLine(t, rest, `^  tunnel\s+none$`)
}

func TestHaltReasonFromASlotWhenTheRaiserIsGone(t *testing.T) {
	tr := buildHaltedRing(t)
	tr.remove("tunnel/halt")
	tr.remove("tunnel/fault")
	lines := render(t, tr, nil)
	firstLine(t, lines, `^\s+RING HALTED\s+heartbeat-fresh on admin, found by tunnel, 1m 30s ago$`)
	firstLine(t, lines, `^  3 of 4 members stopped\.`)
	if row := memberRow(t, lines, "tunnel"); !regexp.MustCompile(`^  tunnel\s+clear\s+`).MatchString(row) {
		t.Errorf("tunnel holds nothing now: %q", row)
	}
}

func TestUnreadableFaultAndHaltAreVisible(t *testing.T) {
	tr := buildClearRing(t)
	tr.put("admin/fault", []byte("not a fault\n"))
	tr.put("admin/halt", []byte("{\"kind\":\"halt\",\n"))
	lines := render(t, tr, nil)
	// No halt could be parsed: nobody is named, and the suffix says why.
	firstLine(t, lines, `^\s+RING HALTED\s+unknown, found by a member \(halt file unreadable\)$`)
	firstLine(t, lines, `^  1 of 4 members stopped\.`)
	if row := memberRow(t, lines, "admin"); !regexp.MustCompile(`^  admin\s+fault\s+`).MatchString(row) {
		t.Errorf("a fault file that will not parse is still a fault file: %q", row)
	}
	firstLine(t, lines, `^\s+failing: \(fault file unreadable\)$`)
}

func TestIncompleteRing(t *testing.T) {
	tr := buildClearRing(t)
	for _, h := range []string{"0000000001.hb", "0000000002.hb", "0000000003.hb"} {
		tr.remove("material/heartbeat/" + h)
	}
	lines := render(t, tr, nil)
	firstLine(t, lines, `^\s+RING INCOMPLETE\s+no readable heartbeat from: material$`)
	noLine(t, lines, `RING CLEAR|RING HALTED`)
	if row := memberRow(t, lines, "material"); !regexp.MustCompile(`^  material\s+no heartbeat$`).MatchString(row) {
		t.Errorf("%q", row)
	}
	// Everyone who read material now reads past: its folder is empty.
	if got := edgeRow(t, lines, "super"); got[3] != "past" {
		t.Errorf("super->material with an empty folder: %v", got)
	}
	// And a heartbeat that does not parse is the same as none.
	tr.put("material/heartbeat/0000000009.hb", []byte("{\"kind\":\"heartbeat\", broken\n"))
	lines = render(t, tr, nil)
	firstLine(t, lines, `^\s+RING INCOMPLETE\s+no readable heartbeat from: material$`)
	// Halt outranks incomplete: a halt in force is a halt in force.
	tr.put("super/halts/admin", haltBytes("admin", "store-readable", "material", 3, fixedNow.Add(-5*time.Second)))
	lines = render(t, tr, nil)
	firstLine(t, lines, `^\s+RING HALTED\s+store-readable on material, found by admin, 5s ago$`)
}

func TestEdgesBehindPastAndNone(t *testing.T) {
	tr := newSynthTree(t)
	for _, m := range []string{"super", "admin", "material"} {
		for seq := int64(1); seq <= 3; seq++ {
			tr.beat(hbSpec{observer: m, seq: seq})
		}
	}
	pruned := sha(hbBytes(hbSpec{observer: "material", seq: 0, ts: fixedNow, cadence: 5}))
	superNewest := tr.hashes["super"][2]
	adminSecond := tr.hashes["admin"][1] // two behind once admin writes its fourth below
	tr.beat(hbSpec{observer: "tunnel", seq: 1, observed: map[string]*string{
		"super": &superNewest, "admin": &adminSecond, "material": &pruned,
	}})
	tunnelNewest := tr.hashes["tunnel"][0]
	materialSecond := tr.hashes["material"][1]
	// admin's newest: super null (none), tunnel newest (ok), material one behind.
	tr.beat(hbSpec{observer: "admin", seq: 4, observed: map[string]*string{
		"super": nil, "tunnel": &tunnelNewest, "material": &materialSecond,
	}})
	lines := render(t, tr, nil)
	if got := edgeRow(t, lines, "tunnel"); strings.Join(got, " ") != "ok · -2 past" {
		t.Errorf("tunnel row: %v", got)
	}
	if got := edgeRow(t, lines, "admin"); strings.Join(got, " ") != "none ok · -1" {
		t.Errorf("admin row: %v", got)
	}
	// A reader with no heartbeat has no edges: every cell says none.
	if got := edgeRow(t, lines, "super"); strings.Join(got, " ") != "· none none none" {
		t.Errorf("super row (observed all null): %v", got)
	}
	firstLine(t, lines, `^\s+-1\s+read the one before that\. Normal: they do not run in step$`)
	firstLine(t, lines, `^\s+none\s+has not read it at all\. Not normal$`)
}

func TestEdgesOfAReaderWithoutAHeartbeat(t *testing.T) {
	tr := buildClearRing(t)
	tr.remove("admin/heartbeat")
	lines := render(t, tr, nil)
	if got := edgeRow(t, lines, "admin"); strings.Join(got, " ") != "none none · none" {
		t.Errorf("admin row: %v", got)
	}
}

func TestCopiesOkPastEmptyUnreadable(t *testing.T) {
	tr := buildClearRing(t)
	// past: a deposit whose bytes are no longer in the author's folder.
	tr.put("super/copy-admin/heartbeat/0000000004.hb", hbBytes(hbSpec{observer: "admin", seq: 4, ts: fixedNow, cadence: 5}))
	// empty: nothing deposited at all.
	tr.remove("super/copy-material/heartbeat/0000000003.hb")
	// unreadable: the newest entry cannot be read as a file.
	mustMkdir(t, filepath.Join(tr.root, "tunnel", "copy", "heartbeat", "0000000004.hb"))
	lines := render(t, tr, nil)
	firstLine(t, lines, `^  COPIES\s+6 of 9 match`)
	if row := copyRow(t, lines, "super/copy-admin"); !strings.HasSuffix(row, " past") {
		t.Errorf("%q", row)
	}
	if row := copyRow(t, lines, "super/copy-material"); !strings.HasSuffix(row, " empty") {
		t.Errorf("%q", row)
	}
	if row := copyRow(t, lines, "tunnel/copy"); !strings.HasSuffix(row, " unreadable") {
		t.Errorf("%q", row)
	}
	if row := copyRow(t, lines, "super/copy-tunnel"); !strings.HasSuffix(row, " ok") {
		t.Errorf("%q", row)
	}
	// A copy folder that is missing altogether reads as empty, not as a crash.
	tr.remove("material/copy-super")
	lines = render(t, tr, nil)
	if row := copyRow(t, lines, "material/copy-super"); !strings.HasSuffix(row, " empty") {
		t.Errorf("%q", row)
	}
	firstLine(t, lines, `^  COPIES\s+5 of 9 match`)
}

func TestSinceColumn(t *testing.T) {
	tr := buildClearRing(t)
	tr.remove("admin/since")
	tr.put("material/since", []byte("garbage\n"))
	lines := render(t, tr, nil)
	if row := memberRow(t, lines, "super"); !regexp.MustCompile(`\s2h 0m\s+7$`).MatchString(row) {
		t.Errorf("%q", row)
	}
	for _, m := range []string{"admin", "material"} {
		if row := memberRow(t, lines, m); !regexp.MustCompile(`\s--\s+7$`).MatchString(row) {
			t.Errorf("%s should read -- for an unreadable since: %q", m, row)
		}
	}
	// With colour on, the missing since is red and the present one grey.
	coloured := renderLines(tr.root, nil, fixedNow, false)
	firstLine(t, coloured, `^  \x1b\[1madmin.*\x1b\[1;31m--\x1b\[0m`)
	firstLine(t, coloured, `^  \x1b\[1msuper.*\x1b\[0;90m2h 0m\x1b\[0m`)
}

func TestStoppedAndBooted(t *testing.T) {
	tr := buildClearRing(t)
	tr.beat(hbSpec{observer: "material", seq: 4, observed: tr.newestOfOthers("material"), stop: true, boot: true})
	tr.beat(hbSpec{observer: "admin", seq: 4, observed: tr.newestOfOthers("admin"), boot: true})
	lines := render(t, tr, nil)
	// STATE is 16 wide and `stopped · booted` fills it, so the sequence
	// follows with no gap.
	if row := memberRow(t, lines, "material"); !regexp.MustCompile(`^  material\s+stopped · booted4\s+`).MatchString(row) {
		t.Errorf("%q", row)
	}
	if row := memberRow(t, lines, "admin"); !regexp.MustCompile(`^  admin\s+clear · booted\s+4\s+`).MatchString(row) {
		t.Errorf("%q", row)
	}
	// stop is a heartbeat's own word, not a halt: the ring is still clear.
	firstLine(t, lines, `RING CLEAR`)
	// And a fault outranks it.
	tr.put("material/fault", faultBytes("material", [2]string{"own-store-writable", ""}))
	lines = render(t, tr, nil)
	if row := memberRow(t, lines, "material"); !regexp.MustCompile(`^  material\s+fault · booted\s+4\s+`).MatchString(row) {
		t.Errorf("%q", row)
	}
	firstLine(t, lines, `^\s+failing: own-store-writable$`)
}

func TestLastBeatAgeColours(t *testing.T) {
	tr := buildClearRing(t)
	tr.beat(hbSpec{observer: "admin", seq: 4, ts: fixedNow.Add(-11 * time.Second), observed: tr.newestOfOthers("admin")})
	tr.beat(hbSpec{observer: "material", seq: 4, ts: fixedNow.Add(-31 * time.Second), observed: tr.newestOfOthers("material")})
	tr.put("super/heartbeat/0000000004.hb", []byte(`{"kind":"heartbeat","version":1,"observer":"super","sequence":4,"timestamp":"soon","cadence_seconds":5,"checks":[],"check_count":0,"observed":{"tunnel":null,"admin":null,"material":null},"previous":null,"boot":null,"stop":false}`+"\n"))
	lines := renderLines(tr.root, nil, fixedNow, false)
	firstLine(t, lines, `^  \x1b\[1mtunnel.*\x1b\[0;32m1s ago`)
	firstLine(t, lines, `^  \x1b\[1madmin.*\x1b\[0;33m11s ago`)
	firstLine(t, lines, `^  \x1b\[1mmaterial.*\x1b\[1;31m31s ago`)
	// A timestamp that will not parse is shown as such, not as a huge age.
	plain := renderLines(tr.root, nil, fixedNow, true)
	if row := firstLine(t, plain, `^  super\s+clear\s+4\s+`); !regexp.MustCompile(`^  super\s+clear\s+4\s+bad time\s+`).MatchString(row) {
		t.Errorf("%q", row)
	}
	firstLine(t, plain, `RING CLEAR`)
}

// ---- read-only by construction ---------------------------------------------

type entry struct {
	size  int64
	mtime int64
	mode  fs.FileMode
}

func snapshot(t *testing.T, root string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// os.Stat rather than d.Info(): on Windows the listing carries the parent
		// index's copy of a subdirectory's times, which NTFS updates lazily, so a
		// snapshot taken from the listing can be stale before any render happens.
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = entry{size: info.Size(), mtime: info.ModTime().UnixNano(), mode: info.Mode()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRenderingWritesNothing(t *testing.T) {
	tr := buildHaltedRing(t)
	tr.put("admin/heartbeat/0000000004.hb", []byte("garbage"))
	tr.put("material/since", []byte("garbage\n"))
	mustMkdir(t, filepath.Join(tr.root, "tunnel", "copy", "heartbeat", "0000000009.hb"))
	before := snapshot(t, tr.root)
	if again := snapshot(t, tr.root); !reflect.DeepEqual(before, again) {
		t.Fatalf("the snapshot method is not stable on this filesystem, so the test cannot prove anything")
	}

	var out bytes.Buffer
	runOnce(tr.root, 0, &out, true)
	renderLines(tr.root, nil, fixedNow, false)
	sampleSequences(tr.root)
	for _, m := range members {
		observingSince(filepath.Join(tr.root, m))
	}

	after := snapshot(t, tr.root)
	if len(before) == 0 || len(before) != len(after) {
		t.Fatalf("entry count changed: %d before, %d after", len(before), len(after))
	}
	for p, b := range before {
		a, ok := after[p]
		if !ok {
			t.Errorf("%s vanished", p)
			continue
		}
		if a != b {
			t.Errorf("%s changed: %+v -> %+v", p, b, a)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s appeared", p)
		}
	}
	if !strings.Contains(out.String(), "RING HALTED") {
		t.Errorf("runOnce printed no frame:\n%s", out.String())
	}
}

func TestMissingTreeIsAVisibleState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")
	lines := renderLines(root, nil, fixedNow, true)
	firstLine(t, lines, `^\s+RING INCOMPLETE\s+no readable heartbeat from: super, tunnel, admin, material$`)
	for _, m := range members {
		memberRow(t, lines, m)
	}
	firstLine(t, lines, `^  COPIES\s+0 of 9 match`)
}

func TestEdgePastWhenTheSubjectFolderHasAnEntryThatCannotBeRead(t *testing.T) {
	tr := buildClearRing(t)
	pruned := sha(hbBytes(hbSpec{observer: "admin", seq: 0, ts: fixedNow, cadence: 5}))
	obs := tr.newestOfOthers("super")
	obs["admin"] = &pruned
	tr.beat(hbSpec{observer: "super", seq: 4, observed: obs})
	mustMkdir(t, filepath.Join(tr.root, "admin", "heartbeat", "0000000004.hb"))
	lines := render(t, tr, nil)
	// A hash not found among the files that could be read is past; an entry
	// that will not open is not a state of its own.
	if got := edgeRow(t, lines, "super"); got[2] != "past" {
		t.Errorf("super->admin with an unreadable entry in admin's folder should say past: %v", got)
	}
	// admin's newest entry is the unreadable one, so admin itself has no
	// readable heartbeat, and the ring says so.
	firstLine(t, lines, `^\s+RING INCOMPLETE\s+no readable heartbeat from: admin$`)
	noLine(t, lines, `unread`)
}

// TestCaptionsAndLegendVerbatim pins every caption, legend row and banner,
// wording and column widths, character for character.
func TestCaptionsAndLegendVerbatim(t *testing.T) {
	tr := buildClearRing(t)
	rates := map[string]*float64{"super": fptr(0.3), "tunnel": fptr(0.3), "admin": fptr(0.3), "material": fptr(0.3)}
	clear := render(t, tr, rates)
	halted := render(t, buildHaltedRing(t), nil)

	want := []string{
		"  GHOSTUNNEL  ·  observer ring                             2026-09-25T12:00:00Z",
		"   RING CLEAR   4 members · 12 directed edges · nothing halted",
		"  MEMBER    STATE           SEQUENCE    LAST BEAT   CYCLE       OBSERVING     CHECKS",
		"  super     clear           3           1s ago      0.3s/5s     2h 0m         7",
		"  EDGES   who has read whose heartbeat, and how recently. The row is the one doing the reading.",
		"            super     tunnel    admin     material  ",
		// The diagonal cell is one column short: the middle dot is two bytes
		// and padding counts bytes.
		"  super     ·        -1        -1        -1        ",
		"          ok      read the newest one",
		"          -1      read the one before that. Normal: they do not run in step",
		"          -2      two behind, and so on",
		"          past    read something so old it has been deleted since",
		"          none    has not read it at all. Not normal",
		"  COPIES    all 9 match       each member writes its heartbeat a second time into another member's",
		"            folder, and that member checks the copy against the original",
		"          super/copy-tunnel     from tunnel     ok",
		"          material/copy-super   from super      ok",
	}
	for _, w := range want {
		if idxOf(clear, "^"+regexp.QuoteMeta(w)+"$") < 0 {
			t.Errorf("clear frame lacks the line %q in:\n%s", w, joined(clear))
		}
	}
	wantHalted := []string{
		"   RING HALTED   heartbeat-fresh on admin, found by tunnel, 1m 30s ago",
		"  4 of 4 members stopped. Clearing is unanimous, so the work stays stopped until every member reads clean.",
		"            failing: heartbeat-fresh:admin, copy-current:material",
		"  HALT SLOTS   delivered into a store by members that cannot be overwritten by its holder",
		"  super     from tunnel",
		"  tunnel    none",
	}
	for _, w := range wantHalted {
		if idxOf(halted, "^"+regexp.QuoteMeta(w)+"$") < 0 {
			t.Errorf("halted frame lacks the line %q in:\n%s", w, joined(halted))
		}
	}
	if got := footerLine(5, true); got != "  watching every 5s, ctrl-c to stop" {
		t.Errorf("footer: %q", got)
	}
	// The legend has exactly five rows.
	legend := 0
	for _, l := range clear {
		if regexp.MustCompile(`^          (ok|-1|-2|past|none)\s`).MatchString(l) {
			legend++
		}
	}
	if legend != 5 {
		t.Errorf("legend has %d rows, want 5:\n%s", legend, joined(clear))
	}
	// Colour codes, by name and number.
	wantColours := map[string]string{"green": "0;32", "red": "1;31", "amber": "0;33", "grey": "0;90", "bold": "1", "cyan": "0;36"}
	if !reflect.DeepEqual(colours, wantColours) {
		t.Errorf("colours: %v", colours)
	}
}
