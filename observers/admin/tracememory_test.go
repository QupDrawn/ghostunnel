package main

// tracememory_test.go proves trace-consistent (tracememory.go): a boot read
// twice must hold the same bytes the second time, a segment may only grow,
// and a new boot starts the memory afresh. Every member carries a
// byte-identical copy of this file.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// tmRead reads the boot under root as a cycle does (traceReadCurrent: the
// root listed once, the decode resumed from st), failing the test on an
// unreadable one.
func tmRead(t *testing.T, st *State, root string) *gtBoot {
	t.Helper()
	b, _, err := traceReadCurrent(st, root)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tmWant(t *testing.T, got []Finding, want ...Finding) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("findings %v, want %v", got, want)
		}
	}
}

func TestTraceConsistentRemembersAndAcceptsGrowth(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:3]...))
	st := &State{}
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	if st.TraceBoot != 1 || len(st.TraceSegments) != 1 || st.TraceSegments["0000000001.trace"].Length != int64(len(gtJoin(gtLines[:3]...))) {
		t.Fatalf("memory after the first read: boot %d, segments %v", st.TraceBoot, st.TraceSegments)
	}
	// Unchanged.
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	// Grown by two lines, and a torn tail after them.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", append(gtJoin(gtLines[:5]...), []byte(`{"kind":"reload","version":1,"sequ`)...))
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	if st.TraceSegments["0000000001.trace"].Length != int64(len(gtJoin(gtLines[:5]...))) {
		t.Fatalf("the torn tail was remembered: %v", st.TraceSegments)
	}
	// The torn line completed, and a second segment.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:6]...))
	gtWriteSegment(t, root, "0000000001", "0000000007.trace", gtJoin(gtLines[6]))
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	if len(st.TraceSegments) != 2 {
		t.Fatalf("memory holds %d segments, want 2", len(st.TraceSegments))
	}
}

func TestTraceConsistentRewrittenPrefix(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	st := &State{}
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	// One past line rewritten in place, same length, still a valid boot:
	// the peer's serial now reads 0b. Every reader of the current boot
	// alone passes this; the memory does not.
	lines := append([]string{}, gtLines...)
	lines[2] = replaceOnce(t, lines[2], `"serial":"0a"`, `"serial":"0b"`)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", padTo(t, gtJoin(lines...), len(gtJoin(gtLines...))))
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)), Finding{Check: "trace-consistent", Subject: "0000000001/0000000001.trace"})
	// And every cycle after, until the boot changes.
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)), Finding{Check: "trace-consistent", Subject: "0000000001/0000000001.trace"})
}

func TestTraceConsistentShrunkSegment(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	st := &State{}
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:4]...))
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)), Finding{Check: "trace-consistent", Subject: "0000000001/0000000001.trace"})
	// Grown back to its old length with the same bytes: the prefix is what
	// was read, so it is consistent again; with other bytes it is not.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
}

func TestTraceConsistentVanishedSegment(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:3]...))
	gtWriteSegment(t, root, "0000000001", "0000000004.trace", gtJoin(gtLines[3:]...))
	st := &State{}
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	if err := os.Remove(filepath.Join(root, "0000000001", "0000000004.trace")); err != nil {
		t.Fatal(err)
	}
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)), Finding{Check: "trace-consistent", Subject: "0000000001/0000000004.trace"})
}

func TestTraceConsistentNewBootResets(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	st := &State{}
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	// The old boot rewritten is not judged once a new boot is current.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:2]...))
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(replaceOnce(t, gtLines[0], `"boot":1`, `"boot":2`)))
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	if st.TraceBoot != 2 || len(st.TraceSegments) != 1 {
		t.Fatalf("memory after a new boot: boot %d, segments %v", st.TraceBoot, st.TraceSegments)
	}
}

func TestTraceConsistentUnreadIsAFinding(t *testing.T) {
	tmWant(t, traceConsistentUnread(), Finding{Check: "trace-consistent"})
}

// ---- tick-fresh ----

func tfNow(t *testing.T, s string) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func TestTickFreshNewestTickIsTheReference(t *testing.T) {
	// gtLines: start at 11:00:00, tick at 11:02:05, accept-error at 11:02:06.
	boot := tmRead(t, &State{}, gtOneBoot(t, gtLines...))
	// 30 s after the tick: within the default max-age.
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:02:35Z"), 0))
	// 31 s after: stale, with the tick's at as subject. The accept-error
	// line after the tick is not the reference, or 11:02:36 would pass.
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:02:36Z"), 0), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:02:05Z"})
	// The max-age is the member's own value.
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:02:36Z"), time.Minute))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:02:35Z"), 10*time.Second), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:02:05Z"})
	// The newest tick, not the first.
	lines := append(append([]string{}, gtLines...), `{"kind":"tick","version":1,"sequence":10,"at":"2026-09-24T11:03:00Z"}`)
	boot = tmRead(t, &State{}, gtOneBoot(t, lines...))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:03:30Z"), 0))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:03:31Z"), 0), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:03:00Z"})
}

func TestTickFreshBeforeTheFirstTick(t *testing.T) {
	// No tick yet: the start line's at is the reference, and no other line
	// refreshes it (the shutdown at 11:02:00 does not).
	boot := tmRead(t, &State{}, gtOneBoot(t, gtLines[:7]...))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:00:30Z"), 0))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:00:31Z"), 0), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:00:00Z"})
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:02:10Z"), 0), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:00:00Z"})
	// Only the start line: the same.
	boot = tmRead(t, &State{}, gtOneBoot(t, gtLines[0]))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:00:30Z"), 0))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:00:31Z"), 0), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:00:00Z"})
}

func TestTickFreshClockAhead(t *testing.T) {
	// A reference more than max-age ahead of this member's clock is not
	// fresh either: two clocks that far apart cannot judge each other.
	boot := tmRead(t, &State{}, gtOneBoot(t, gtLines...))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:01:35Z"), 0))
	tmWant(t, tickFreshFindings(boot, tfNow(t, "2026-09-24T11:01:34Z"), 0), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:02:05Z"})
}

func TestTickFreshNewBootResets(t *testing.T) {
	root := t.TempDir()
	st := &State{}
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	now := tfNow(t, "2026-09-24T12:00:00Z")
	tmWant(t, tickFreshFindings(tmRead(t, st, root), now, 0), Finding{Check: "tick-fresh", Subject: "2026-09-24T11:02:05Z"})
	// A new boot started 15 s ago, no tick yet: fresh, whatever boot 1 was.
	start := replaceOnce(t, replaceOnce(t, gtLines[0], `"boot":1`, `"boot":2`), "2026-09-24T11:00:00Z", "2026-09-24T11:59:45Z")
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(start))
	tmWant(t, tickFreshFindings(tmRead(t, st, root), now, 0))
}

func TestTickFreshUnreadIsAFinding(t *testing.T) {
	tmWant(t, tickFreshUnread(), Finding{Check: "tick-fresh"})
}

// TestTickFreshIsNotTheScheduleCheck: the proxy's tick freshness and SPEC
// 14.2's schedule freshness (traces.go, subject a schedule name) are two
// checks with two identifiers. The tick form is tick-fresh, it is local
// through the member's own Identifiers and not through structuralLocal
// (which holds the schedule form), and neither its found nor its unread
// finding is spelled like the schedule check.
func TestTickFreshIsNotTheScheduleCheck(t *testing.T) {
	if checkTickFresh != "tick-fresh" {
		t.Fatalf("checkTickFresh = %q, want tick-fresh", checkTickFresh)
	}
	if !structuralLocal["trace-fresh"] {
		t.Fatal("the schedule check trace-fresh must stay in structuralLocal")
	}
	if structuralLocal[checkTickFresh] {
		t.Fatalf("%s is a per-member check and must not be in structuralLocal", checkTickFresh)
	}
	boot := tmRead(t, &State{}, gtOneBoot(t, gtLines...))
	for _, f := range append(tickFreshFindings(boot, tfNow(t, "2026-09-24T11:59:59Z"), 0), tickFreshUnread()...) {
		if f.Check != checkTickFresh {
			t.Fatalf("tick finding spelled %q, want %q", f.Check, checkTickFresh)
		}
	}
}

// replaceOnce replaces old with new in s, failing the test when old is not
// there.
func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	i := indexOf(s, old)
	if i < 0 {
		t.Fatalf("%q not in %q", old, s)
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// padTo fails the test unless b already has length n: the rewritten line
// must keep the segment's length, or the test would be proving a shrink.
func padTo(t *testing.T, b []byte, n int) []byte {
	t.Helper()
	if len(b) != n {
		t.Fatalf("rewritten segment is %d bytes, want %d", len(b), n)
	}
	return b
}

// One pass: a read resumed from memory sums the prefix at the remembered
// length and at its end, so trace-consistent compares the sum the read
// already took and hashes nothing a second time.
func TestTraceReadSumsAtTheRememberedLength(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:3]...))
	st := &State{}
	tmWant(t, traceConsistentFindings(st, tmRead(t, st, root)))
	remembered := st.TraceSegments["0000000001.trace"].Length
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	b := tmRead(t, st, root)
	sums := b.Segments[0].Sums
	if _, ok := sums[remembered]; !ok {
		t.Fatalf("the read did not sum at the remembered length %d: %v", remembered, sums)
	}
	if _, ok := sums[int64(len(b.Segments[0].Prefix))]; !ok {
		t.Fatalf("the read did not sum at the prefix's end: %v", sums)
	}
	if sums[remembered] != hashPrefix(b.Segments[0].Prefix[:remembered]) {
		t.Fatal("the sum at the remembered length is not the hash of that prefix")
	}
	tmWant(t, traceConsistentFindings(st, b))
}

// ---- boot-ended ----

// tmEndedNow is the member's clock in the boot-ended tests: an hour after
// gtLines's boot, so a boot made of those lines has long stopped writing.
const tmEndedNow = "2026-09-24T12:00:00Z"

func tmNow(t *testing.T, at string) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, at)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

// tmAbortedBoot is a boot that ended badly: start, accept, handshake and
// acl of connection 1, which is never closed; a failed accept; a torn last
// line; no shutdown line.
func tmAbortedBoot(t *testing.T) []byte {
	t.Helper()
	lines := append([]string{}, gtLines[:4]...)
	lines = append(lines, replaceOnce(t, gtLines[8], `"sequence":9`, `"sequence":5`))
	return append(gtJoin(lines...), []byte(`{"kind":"accept-error","version":1,"sequ`)...)
}

// tmSecondBoot is the start line of boot 2, the process that came back.
func tmSecondBoot(t *testing.T) []byte {
	t.Helper()
	two := replaceOnce(t, gtLines[0], `"boot":1`, `"boot":2`)
	two = replaceOnce(t, two, `"pid":4242`, `"pid":4343`)
	two = replaceOnce(t, two, `"at":"2026-09-24T11:00:00Z"`, `"at":"2026-09-24T11:59:00Z"`)
	return gtJoin(two)
}

// tmCycle is one cycle's read and the two memories over it, as every
// member's Run does them: the boot read last cycle is what boot-ended
// judges once another is current.
func tmCycle(t *testing.T, st *State, root string, now time.Time) []Finding {
	t.Helper()
	b := tmRead(t, st, root)
	previous := st.TraceBoot
	tmWant(t, traceConsistentFindings(st, b))
	return bootEndedFindings(st, root, previous, b, now, 0)
}

func TestBootEndedJudgedOnceAfterTheChange(t *testing.T) {
	now := tmNow(t, tmEndedNow)
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", tmAbortedBoot(t))
	st := &State{}
	// Cycle 1: boot 1 is current; nothing has ended.
	tmWant(t, tmCycle(t, st, root, now))
	// Cycle 2: boot 2 is current, so boot 1 ended, and it is judged.
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", tmSecondBoot(t))
	tmWant(t, tmCycle(t, st, root, now),
		Finding{Check: "boot-ended", Subject: "0000000001:aborted"},
		Finding{Check: "boot-ended", Subject: "0000000001:torn"},
		Finding{Check: "boot-ended", Subject: "0000000001:conn:1"},
		Finding{Check: "boot-ended", Subject: "0000000001:accept-error:accept tcp 127.0.0.1:8443: too many open files"})
	if len(st.BootsEnded) != 0 {
		t.Fatalf("a judged boot is still pending: %v", st.BootsEnded)
	}
	// Cycle 3 and after: never again by this process.
	tmWant(t, tmCycle(t, st, root, now))
	tmWant(t, tmCycle(t, st, root, now))
	// A member that started after the restart never saw boot 1 end.
	fresh := &State{}
	tmWant(t, tmCycle(t, fresh, root, now))
	tmWant(t, tmCycle(t, fresh, root, now))
}

func TestBootEndedWaitsWhileThePreviousBootMayStillWrite(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", tmAbortedBoot(t))
	st := &State{}
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:10Z")))
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", tmSecondBoot(t))
	// Boot 1's newest line is 14 s old: within -tick-max-age, it may be a
	// second live process (boot-ambiguous's finding); boot-ended waits.
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:20Z")))
	if len(st.BootsEnded) != 1 || st.BootsEnded[0] != 1 {
		t.Fatalf("boot 1 is not pending: %v", st.BootsEnded)
	}
	// Older than -tick-max-age: it has ended, and is judged now, once.
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:37Z")),
		Finding{Check: "boot-ended", Subject: "0000000001:aborted"},
		Finding{Check: "boot-ended", Subject: "0000000001:torn"},
		Finding{Check: "boot-ended", Subject: "0000000001:conn:1"},
		Finding{Check: "boot-ended", Subject: "0000000001:accept-error:accept tcp 127.0.0.1:8443: too many open files"})
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:38Z")))
}

func TestBootEndedCleanEndIsNothing(t *testing.T) {
	now := tmNow(t, tmEndedNow)
	root := t.TempDir()
	// Start, one connection served and closed, a reload, a shutdown line.
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines[:7]...))
	st := &State{}
	tmWant(t, tmCycle(t, st, root, now))
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", tmSecondBoot(t))
	tmWant(t, tmCycle(t, st, root, now))
	if len(st.BootsEnded) != 0 {
		t.Fatalf("a judged boot is still pending: %v", st.BootsEnded)
	}
}

func TestBootEndedFailedAcceptsOnlyBeforeTheAbort(t *testing.T) {
	now := tmNow(t, tmEndedNow)
	root := t.TempDir()
	// The failed accept is followed by a tick a minute later: it did not
	// precede the abort within -tick-max-age. No shutdown line, the
	// connection open, so aborted and conn:1 stand; nothing is torn.
	lines := append([]string{}, gtLines[:4]...)
	lines = append(lines, replaceOnce(t, gtLines[8], `"sequence":9`, `"sequence":5`))
	tick := replaceOnce(t, gtLines[7], `"sequence":8`, `"sequence":6`)
	tick = replaceOnce(t, tick, `"at":"2026-09-24T11:02:05Z"`, `"at":"2026-09-24T11:03:00Z"`)
	lines = append(lines, tick)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines...))
	st := &State{}
	tmWant(t, tmCycle(t, st, root, now))
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", tmSecondBoot(t))
	tmWant(t, tmCycle(t, st, root, now),
		Finding{Check: "boot-ended", Subject: "0000000001:aborted"},
		Finding{Check: "boot-ended", Subject: "0000000001:conn:1"})
}

func TestBootEndedUnreadablePreviousBoot(t *testing.T) {
	now := tmNow(t, tmEndedNow)
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", tmAbortedBoot(t))
	st := &State{}
	tmWant(t, tmCycle(t, st, root, now))
	// The boot this member read is gone by the time it has ended: the
	// check cannot run on it, which is a finding, once.
	if err := os.RemoveAll(filepath.Join(root, "0000000001")); err != nil {
		t.Fatal(err)
	}
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", tmSecondBoot(t))
	tmWant(t, tmCycle(t, st, root, now), Finding{Check: "boot-ended", Subject: "0000000001:unreadable"})
	tmWant(t, tmCycle(t, st, root, now))
}

func TestBootEndedEmptyPreviousBootIsAborted(t *testing.T) {
	now := tmNow(t, tmEndedNow)
	root := t.TempDir()
	// A boot directory with no segment: a process that died before its
	// first line. Read as current it is a boot with no records.
	if err := os.MkdirAll(filepath.Join(root, "0000000001"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := &State{}
	tmWant(t, tmCycle(t, st, root, now))
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", tmSecondBoot(t))
	tmWant(t, tmCycle(t, st, root, now), Finding{Check: "boot-ended", Subject: "0000000001:aborted"})
}

func TestBootEndedPendingBootCurrentAgainIsDropped(t *testing.T) {
	now := tmNow(t, tmEndedNow)
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(gtLines...))
	// Boot 1 was pending (its successor's directory is gone): it is the
	// current boot again, so it has not ended, and is dropped unjudged.
	st := &State{BootsEnded: []int64{1}}
	b := tmRead(t, st, root)
	tmWant(t, bootEndedFindings(st, root, 1, b, now, 0))
	if len(st.BootsEnded) != 0 {
		t.Fatalf("the current boot is still pending: %v", st.BootsEnded)
	}
}

// A pending boot is read under every rule at every look and its lines
// decoded once: the looks while it waits to end decode nothing of it
// again, a byte rewritten in place is decoded afresh (the memory is keyed
// by the bytes' hash, as the current boot's is), and the memory goes with
// the judgement.
func TestBootEndedPendingBootIsDecodedOnce(t *testing.T) {
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", tmAbortedBoot(t))
	st := &State{}
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:10Z")))
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", tmSecondBoot(t))
	decodes := gtCountDecodes(t)
	// The first look: boot 2 is current (one line, decoded), boot 1 is
	// pending and its newest line 14 s old, so it is read whole and its
	// five complete lines decoded.
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:20Z")))
	if *decodes != 6 {
		t.Fatalf("the first look decoded %d lines, want 6", *decodes)
	}
	if st.BootEndedDecode == nil || st.BootEndedDecode.Boot != 1 {
		t.Fatalf("no decode memory of the pending boot: %+v", st.BootEndedDecode)
	}
	// Another look while it waits: read and hashed again, nothing decoded.
	*decodes = 0
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:21Z")))
	if *decodes != 0 {
		t.Fatalf("the second look decoded %d lines, want 0", *decodes)
	}
	// A byte of the pending boot rewritten in place, same length: the
	// remembered prefix no longer hashes the same, and every line is
	// decoded again.
	seg := filepath.Join(root, "0000000001", "0000000001.trace")
	data, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := bytes.Replace(data, []byte(`"remote":"10.0.0.7:51000"`), []byte(`"remote":"10.0.0.7:51001"`), 1)
	if bytes.Equal(rewritten, data) || len(rewritten) != len(data) {
		t.Fatal("the rewrite did not change one byte in place")
	}
	if err := os.WriteFile(seg, rewritten, 0o644); err != nil {
		t.Fatal(err)
	}
	*decodes = 0
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:22Z")))
	if *decodes != 5 {
		t.Fatalf("the look after the rewrite decoded %d lines, want 5", *decodes)
	}
	// Ended: judged once, from the memory (nothing decoded), and the
	// memory goes with the judgement.
	*decodes = 0
	tmWant(t, tmCycle(t, st, root, tmNow(t, "2026-09-24T11:02:37Z")),
		Finding{Check: "boot-ended", Subject: "0000000001:aborted"},
		Finding{Check: "boot-ended", Subject: "0000000001:torn"},
		Finding{Check: "boot-ended", Subject: "0000000001:conn:1"},
		Finding{Check: "boot-ended", Subject: "0000000001:accept-error:accept tcp 127.0.0.1:8443: too many open files"})
	if *decodes != 0 {
		t.Fatalf("the judgement decoded %d lines, want 0", *decodes)
	}
	if st.BootEndedDecode != nil || len(st.BootsEnded) != 0 {
		t.Fatalf("memory kept after the judgement: %+v, pending %v", st.BootEndedDecode, st.BootsEnded)
	}
}
