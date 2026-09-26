package main

// race_test.go covers the benign read/write races a reader tolerates: an
// entry pruned between the listing and the read (SPEC 6.1 C5), a staging
// file renamed away between the listing and the stat (C3, K2, H4), a copy
// one entry above a ceiling that went stale between step 4 and step 5 (SPEC
// 9 K5), and an original entry listed but not read (K5). Each is enacted on
// disk in the state the race leaves, or through readEntry where only the gap
// between the listing and the read can hold it. The tests are not parallel:
// readEntry is package state.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// entryHook installs f as the reader's entry read for this test and restores
// the previous one afterwards.
func entryHook(t *testing.T, f func(string, int64) ([]byte, bool, error)) {
	t.Helper()
	prev := readEntry
	readEntry = f
	t.Cleanup(func() { readEntry = prev })
}

// hbPath is the on-disk path of stores/<store>/<dir...>/<seq>.hb under tmp.
func hbPath(tmp, store string, seq int64, dir ...string) string {
	parts := append([]string{tmp, "stores", store}, dir...)
	parts = append(parts, heartbeatName(seq))
	return filepath.Join(parts...)
}

// nextEntry encodes the heartbeat of sequence seq that follows the entry
// seq-1 in dir: the same content, the timestamp moved on by one cadence,
// previous the hash of the predecessor's bytes on disk.
func nextEntry(t *testing.T, dir string, seq int64) []byte {
	t.Helper()
	prev, err := os.ReadFile(filepath.Join(dir, heartbeatName(seq-1)))
	if err != nil {
		t.Fatal(err)
	}
	hb, err := parseHeartbeat(prev, sampleMembers)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := parseTimestamp(hb.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256Hex(prev)
	hb.Sequence = seq
	hb.Timestamp = formatTimestamp(ts.Add(time.Duration(hb.CadenceSeconds) * time.Second))
	hb.Previous = &h
	hb.Boot = nil
	b, err := encodeHeartbeat(hb)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

// cycleFindings runs one cycle and returns its failing set as keys.
func cycleFindings(t *testing.T, cfg *Config, st *State) ([]string, *Outcome) {
	t.Helper()
	out, err := RunCycle(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(out.Failing))
	for _, f := range out.Failing {
		keys = append(keys, findingKey(f.Check, f.SubjectPtr()))
	}
	return keys, out
}

// --- C5: pruned between the listing and the read ------------------------

// A listed entry its owner prunes before the reader reaches it stays a
// listed name with nothing read and nothing parsed, and there is no finding
// at all: not S5 for the entry, not I3 for the chain, not I7 or copy-current
// for the copy that still holds it.
func TestEntryPrunedBetweenListAndRead(t *testing.T) {
	baseCfg, baseSt, _ := fixtureCopy(t, "healthy-ring")
	want, _ := cycleFindings(t, baseCfg, baseSt)

	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	victim := hbPath(tmp, "material", 41, "heartbeat")
	removed := false
	entryHook(t, func(p string, max int64) ([]byte, bool, error) {
		if p == victim && !removed {
			removed = true
			mustRemove(t, p)
		}
		return readBounded(p, max)
	})
	got, out := cycleFindings(t, cfg, st)
	if !removed {
		t.Fatal("the read never reached the listed entry")
	}
	if !sameSet(want, got) {
		t.Errorf("failing set changed: healthy %v, with the race %v", want, got)
	}
	if out.Verdicts["material"] != VerdictAlive {
		t.Errorf("verdict: want alive, got %s", out.Verdicts["material"])
	}
}

// An entry still present and still unreadable is S5, and it is not
// compared with its copy (K5), so there is no I7 for it.
func TestEntryPresentButUnreadableIsS5(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	victim := hbPath(tmp, "material", 41, "heartbeat")
	entryHook(t, func(p string, max int64) ([]byte, bool, error) {
		if p == victim {
			return nil, false, errors.New("held elsewhere")
		}
		return readBounded(p, max)
	})
	_, out := cycleFindings(t, cfg, st)
	if !hasFinding(out, "S5", "material/heartbeat/0000000041.hb") {
		t.Errorf("S5 missing from %v", out.Failing)
	}
	if hasFinding(out, "I7", "material") {
		t.Errorf("I7 fired for an original listed but not read: %v", out.Failing)
	}
	if hasFinding(out, "copy-current", "material") {
		t.Errorf("copy-current fired: %v", out.Failing)
	}
}

// --- C3, K2, H4: a staging file renamed away ------------------------------

// A staging file that is gone by the time it is stat'ed was renamed into
// place by a live writer; it is not judged.
func TestStagingRenamedAwayIsNotJudged(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	r := newReader(cfg, st)
	gone := hbPath(tmp, "material", 45, "heartbeat") + ".tmp"
	if r.stagingStale(gone) {
		t.Error("a staging file that is gone was judged stale")
	}
}

// A staging file present with an old modification time is stale (C3); a
// fresh one is nothing at all.
func TestStagingPresentIsJudgedByAge(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	old := hbPath(tmp, "material", 45, "heartbeat") + ".tmp"
	writeFile(t, old, []byte("partial"))
	if err := os.Chtimes(old, cfg.Now, cfg.Now.Add(-2*cfg.StagingStaleAfter)); err != nil {
		t.Fatal(err)
	}
	fresh := hbPath(tmp, "admin", 45, "heartbeat") + ".tmp"
	writeFile(t, fresh, []byte("partial"))
	if err := os.Chtimes(fresh, cfg.Now, cfg.Now); err != nil {
		t.Fatal(err)
	}
	_, out := cycleFindings(t, cfg, st)
	if !hasFinding(out, "staging-fresh", "material/heartbeat/0000000045.hb.tmp") {
		t.Errorf("staging-fresh missing from %v", out.Failing)
	}
	if hasFinding(out, "staging-fresh", "admin/heartbeat/0000000045.hb.tmp") {
		t.Errorf("staging-fresh fired for a fresh staging file: %v", out.Failing)
	}
}

// --- K4-K6: the copy against the original as listed at step 4 ------------

var materialCopy = copyDir{Store: "tunnel", Dir: "copy", Author: "material"}

// kStep4 runs the member pass over material on a healthy ring (SPEC 13 step
// 4) and returns the reader ready for step 5.
func kStep4(t *testing.T) (*reader, string) {
	t.Helper()
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	r := newReader(cfg, st)
	r.verdictFor("material")
	if len(r.findings) != 0 {
		t.Fatalf("step 4 on a healthy ring found %v", r.findings)
	}
	if r.entries["material"] == nil {
		t.Fatal("step 4 did not record material's own folder")
	}
	return r, tmp
}

// The author advanced between step 4 and step 5, own store first and copy
// second: the copy is one above the ceiling as listed at step 4, and the
// author's folder holds that entry now. Not I7.
func TestCopyAheadOfStaleCeilingIsNotI7(t *testing.T) {
	r, tmp := kStep4(t)
	orig := filepath.Join(tmp, "stores", "material", "heartbeat")
	next := nextEntry(t, orig, 45)
	writeFile(t, hbPath(tmp, "material", 45, "heartbeat"), next)
	writeFile(t, hbPath(tmp, "tunnel", 45, "copy", "heartbeat"), next)
	r.runK(materialCopy)
	if len(r.findings) != 0 {
		t.Errorf("an honest copy one ahead of a stale ceiling: %v", r.findings)
	}
}

// The copy is above the ceiling and the author's folder, listed again now,
// still does not hold the entry: a record the author never published, I7.
func TestCopyAheadOfFreshCeilingIsI7(t *testing.T) {
	r, tmp := kStep4(t)
	orig := filepath.Join(tmp, "stores", "material", "heartbeat")
	writeFile(t, hbPath(tmp, "tunnel", 45, "copy", "heartbeat"), nextEntry(t, orig, 45))
	r.runK(materialCopy)
	if !r.seen[Finding{Check: "I7", Subject: "material"}] {
		t.Errorf("I7 missing from %v", r.findings)
	}
	if r.seen[Finding{Check: "copy-current", Subject: "material"}] {
		t.Errorf("copy-current fired: %v", r.findings)
	}
}

// An original entry listed at step 4 but not read (present and unreadable:
// S5 at the author) is not compared with its copy: no I7 for it.
func TestOriginalListedNotReadIsNotCompared(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	victim := hbPath(tmp, "material", 43, "heartbeat")
	entryHook(t, func(p string, max int64) ([]byte, bool, error) {
		if p == victim {
			return nil, false, errors.New("held elsewhere")
		}
		return readBounded(p, max)
	})
	r := newReader(cfg, st)
	r.verdictFor("material")
	if !r.seen[Finding{Check: "S5", Subject: "material/heartbeat/0000000043.hb"}] {
		t.Fatalf("S5 missing from step 4: %v", r.findings)
	}
	r.runK(materialCopy)
	if r.seen[Finding{Check: "I7", Subject: "material"}] {
		t.Errorf("I7 fired for an original listed but not read: %v", r.findings)
	}
	if r.seen[Finding{Check: "copy-current", Subject: "material"}] {
		t.Errorf("copy-current fired: %v", r.findings)
	}
}

// A copy holding an entry below the floor the step-4 listing showed is an
// unmaintained copy: copy-current, and not I7.
func TestCopyBehindListedFloorIsCopyCurrent(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	mustRemove(t, hbPath(tmp, "material", 41, "heartbeat"))
	r := newReader(cfg, st)
	r.verdictFor("material")
	if len(r.findings) != 0 {
		t.Fatalf("step 4 over a folder pruned to 42..44 found %v", r.findings)
	}
	r.runK(materialCopy)
	if !r.seen[Finding{Check: "copy-current", Subject: "material"}] {
		t.Errorf("copy-current missing from %v", r.findings)
	}
	if r.seen[Finding{Check: "I7", Subject: "material"}] {
		t.Errorf("I7 fired for a copy that is merely behind: %v", r.findings)
	}
}

// A copy entry in the window whose bytes differ from the original read at
// step 4 is I7.
func TestCopyDifferingBytesIsI7(t *testing.T) {
	r, tmp := kStep4(t)
	p := hbPath(tmp, "tunnel", 44, "copy", "heartbeat")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := parseHeartbeat(b, sampleMembers)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := parseTimestamp(hb.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	hb.Timestamp = formatTimestamp(ts.Add(time.Second))
	altered, err := encodeHeartbeat(hb)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, altered)
	r.runK(materialCopy)
	if !r.seen[Finding{Check: "I7", Subject: "material"}] {
		t.Errorf("I7 missing from %v", r.findings)
	}
}
