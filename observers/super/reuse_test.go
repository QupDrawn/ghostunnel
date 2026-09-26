package main

// reuse_test.go proves the two reuses a cycle makes and the bounds on them:
// the parse of a heartbeat entry is reused across and within cycles only
// for bytes with the same SHA-256 (chain.go, parseMemory), and within one
// cycle a directory listed twice or a file read twice is served from the
// first listing or read (cycle.go, snapshot), with the reads that must stay
// live staying live. Every member carries a byte-identical copy of this
// file. The tests are not parallel: the hooks are package state.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseHook counts the parses of the rest of the test and the distinct
// byte strings parsed.
func parseHook(t *testing.T) (calls *int, distinct map[string]bool) {
	t.Helper()
	prev := parseEntryBytes
	n := 0
	seen := map[string]bool{}
	parseEntryBytes = func(b []byte, members []string) (*Heartbeat, error) {
		n++
		seen[sha256Hex(b)] = true
		return prev(b, members)
	}
	t.Cleanup(func() { parseEntryBytes = prev })
	return &n, seen
}

// ---- the parse of a heartbeat entry, once per distinct bytes --------

// A cycle parses each distinct byte string once: a copy entry whose bytes
// are its original's is that parse. A second cycle over an unchanged ring
// parses nothing: every entry's bytes were parsed last cycle.
func TestHeartbeatParsedOncePerDistinctBytes(t *testing.T) {
	cfg, st, _ := fixtureCopy(t, "healthy-ring")
	calls, distinct := parseHook(t)
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	if *calls == 0 || *calls != len(distinct) {
		t.Fatalf("first cycle: %d parses of %d distinct byte strings", *calls, len(distinct))
	}
	*calls = 0
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("second cycle over an unchanged ring: %d parses, want 0", *calls)
	}
}

// An entry rewritten in place between two cycles, same length, so that it
// no longer parses as its author's: the second cycle parses the new bytes
// and reports S5. A memory keyed by anything but the bytes' hash would hand
// the second cycle the first cycle's parse.
func TestHeartbeatModifiedInPlaceIsParsedAfresh(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	p := hbPath(tmp, "admin", 44, "heartbeat")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(b), `"observer":"admin"`, `"observer":"admim"`, 1)
	if len(altered) != len(b) || altered == string(b) {
		t.Fatalf("the rewrite did not keep the length or did nothing")
	}
	writeFile(t, p, []byte(altered))
	calls, _ := parseHook(t)
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Fatalf("the rewritten entry alone should be parsed: %d parses", *calls)
	}
	if !hasFinding(out, "S5", "admin/heartbeat/0000000044.hb") {
		t.Fatalf("S5 missing for the rewritten entry: %v", out.Failing)
	}
}

// The memory is bounded: after a cycle it holds the parses of the bytes
// that cycle read and nothing else.
func TestHeartbeatParseMemoryIsBounded(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	calls, distinct := parseHook(t)
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	if st.Parses == nil {
		t.Fatal("nothing remembered")
	}
	first := len(distinct)
	if len(st.Parses.entries) != first {
		t.Fatalf("after the first cycle the memory holds %d entries; the cycle read %d distinct byte strings", len(st.Parses.entries), first)
	}
	// Admin's oldest entry pruned and a new one published: the pruned
	// entry's bytes are read by nothing this cycle, so its parse is gone
	// after it, and the new entry's is there.
	dir := filepath.Join(tmp, "stores", "admin", "heartbeat")
	pruned, err := os.ReadFile(hbPath(tmp, "admin", 41, "heartbeat"))
	if err != nil {
		t.Fatal(err)
	}
	fresh := nextEntry(t, dir, 45)
	writeFile(t, hbPath(tmp, "admin", 45, "heartbeat"), fresh)
	mustRemove(t, hbPath(tmp, "admin", 41, "heartbeat"))
	*calls = 0
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	if *calls != 1 {
		t.Fatalf("the new entry alone should be parsed: %d parses", *calls)
	}
	if st.Parses.holds(sha256Hex(pruned)) {
		t.Fatal("the pruned entry's parse is still remembered")
	}
	if !st.Parses.holds(sha256Hex(fresh)) {
		t.Fatal("the new entry's parse is not remembered")
	}
	if n := len(st.Parses.entries); n != first {
		t.Fatalf("the memory holds %d entries, want %d (one out, one in)", n, len(distinct))
	}
	// An unchanged cycle parses nothing and changes nothing.
	*calls = 0
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 || len(st.Parses.entries) != first {
		t.Fatalf("unchanged cycle: %d parses, %d entries", *calls, len(st.Parses.entries))
	}
}

// ---- one cycle is one look at the store -----------------------------

// readHooks counts, for the rest of the test, the listings, whole reads
// and bounded reads beneath the snapshot, by path.
func readHooks(t *testing.T) (lists, reads map[string]int) {
	t.Helper()
	lists, reads = map[string]int{}, map[string]int{}
	prevList, prevWhole, prevEntry := listDir, readWhole, readEntry
	listDir = func(p string) ([]os.DirEntry, error) { lists[p]++; return prevList(p) }
	readWhole = func(p string) ([]byte, error) { reads[p]++; return prevWhole(p) }
	readEntry = func(p string, max int64) ([]byte, bool, error) { reads[p]++; return prevEntry(p, max) }
	t.Cleanup(func() { listDir, readWhole, readEntry = prevList, prevWhole, prevEntry })
	return lists, reads
}

// A healthy cycle lists each directory once and reads each file once: the
// own heartbeat/ (I5 and procedure C), the own halts/ (procedure H and the
// in-force walk), each peer's heartbeat/ (V2 and procedure C), and the own
// heartbeat entries (I5 hashes them, procedure C parses them).
func TestCycleListsAndReadsEachPathOnce(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	lists, reads := readHooks(t)
	if _, err := RunCycle(cfg, st); err != nil {
		t.Fatal(err)
	}
	for p, n := range lists {
		if n != 1 {
			t.Errorf("%s listed %d times", p, n)
		}
	}
	for p, n := range reads {
		if n != 1 {
			t.Errorf("%s read %d times", p, n)
		}
	}
	for _, p := range []string{
		filepath.Join(tmp, "stores", "tunnel", "heartbeat"),
		filepath.Join(tmp, "stores", "tunnel", "halts"),
		filepath.Join(tmp, "stores", "admin", "heartbeat"),
	} {
		if lists[p] != 1 {
			t.Errorf("%s listed %d times, want 1", p, lists[p])
		}
	}
	if own := hbPath(tmp, "tunnel", 44, "heartbeat"); reads[own] != 1 {
		t.Errorf("%s read %d times, want 1", own, reads[own])
	}
}

// The bound. An entry the author publishes between the cycle's first
// listing of its folder (V2) and procedure C's is judged by the next
// cycle: this cycle records what it first listed.
func TestChangeBetweenTwoReadsIsJudgedNextCycle(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	dir := filepath.Join(tmp, "stores", "material", "heartbeat")
	next := nextEntry(t, dir, 45)
	published := false
	prev := listDir
	listDir = func(p string) ([]os.DirEntry, error) {
		des, err := prev(p)
		if p == dir && !published {
			published = true
			writeFile(t, hbPath(tmp, "material", 45, "heartbeat"), next)
		}
		return des, err
	}
	t.Cleanup(func() { listDir = prev })
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("the folder was never listed")
	}
	b44, err := os.ReadFile(hbPath(tmp, "material", 44, "heartbeat"))
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Publish.Observed["material"]; got == nil || *got != sha256Hex(b44) {
		t.Fatalf("this cycle observed material at %v, want the entry it first listed (44)", got)
	}
	if len(out.Failing) != 0 {
		t.Fatalf("a change between two reads produced findings: %v", out.Failing)
	}
	// The next cycle sees the entry.
	st.Basis = out.Publish.Observed
	out, err = RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Publish.Observed["material"]; got == nil || *got != sha256Hex(next) {
		t.Fatalf("the next cycle observed material at %v, want 45", got)
	}
}

// isGone stats the disk now, whatever the cycle saw of the path before: an
// entry the cycle stat'ed present and its owner then pruned is gone.
func TestIsGoneStatsLive(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	r := newReader(cfg, st)
	p := hbPath(tmp, "material", 41, "heartbeat")
	if !r.exists("material", "heartbeat", heartbeatName(41)) {
		t.Fatal("the entry is not there to begin with")
	}
	mustRemove(t, p)
	if !isGone(p, errors.New("held elsewhere")) {
		t.Fatal("a pruned entry the cycle had seen was not shown gone")
	}
	if !r.exists("material", "heartbeat", heartbeatName(41)) {
		t.Fatal("the snapshot changed under the cycle")
	}
}

// Step 11 reads the disk now: a halt or a slot that appeared after the
// cycle's look at the store decides the write, because the write is what
// the answer is for.
func TestStep11ReadsLive(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	r := newReader(cfg, st)
	if r.exists("tunnel", "halt") || r.exists("super", "halts", "tunnel") {
		t.Fatal("halt or slot present to begin with")
	}
	// A halt appears after the cycle's look: a raise does not write it
	// again.
	writeFile(t, filepath.Join(tmp, "stores", "tunnel", "halt"), []byte("{}"))
	r.fail("I3", "admin")
	out := &Outcome{Publish: PublishRecord{Sequence: 45}}
	r.decideHalts(out, false, nil)
	if !out.Halt.Writes || out.Halt.OwnHaltWritten {
		t.Fatalf("raise: %+v", out.Halt)
	}
	// A slot appears after the look: the clear removes it.
	r2 := newReader(cfg, st)
	if r2.exists("super", "halts", "tunnel") {
		t.Fatal("slot present to begin with")
	}
	writeFile(t, filepath.Join(tmp, "stores", "super", "halts", "tunnel"), []byte("{}"))
	mustRemove(t, filepath.Join(tmp, "stores", "tunnel", "halt"))
	out = &Outcome{Publish: PublishRecord{Sequence: 45}}
	r2.decideHalts(out, false, nil)
	if out.Clears == nil {
		t.Fatalf("clear: %+v", out)
	}
	found := false
	for _, rel := range out.Clears.Removes {
		if rel == "super/halts/tunnel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the slot that appeared after the look is not cleared: %v", out.Clears.Removes)
	}
}
