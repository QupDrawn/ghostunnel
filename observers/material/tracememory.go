package main

// tracememory.go is trace-consistent (SPEC 14.3): the proxy's trace is
// appended and never rewritten, so what this member read of the current
// boot last cycle must still be there, byte for byte, this cycle. Each
// member keeps in its State, for the current boot and each segment it has
// read, the length of the prefix of complete lines it read and the SHA-256
// of that prefix (the last segment's torn tail, a line still being
// written, is not part of it). On the next read the same prefix must hash
// the same: a segment may only grow. A prefix that changed, a segment
// shorter than it was, or a segment of the current boot that is gone fails
// the check with the segment as subject. A new boot resets the memory.
//
// A reader that judges only the newest lines passes a past line rewritten
// in place; this is the check that does not. Every member carries a
// byte-identical copy of this file.
//
// It also holds boot-ended (SPEC 14.3), the other memory across cycles of
// the proxy's trace: the boot this member read last cycle, once another
// boot is current, is the boot that ended, and its tail is judged once,
// by this process, and never again.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"time"
)

// checkTraceConsistent is the identifier (SPEC 15). Subject: the segment,
// relative to gt/, or null when the trace could not be read at all.
const checkTraceConsistent = "trace-consistent"

// checkTickFresh is the identifier of the proxy trace's freshness (SPEC
// 15): the newest tick of the current boot, or the start line before the
// first tick, is within the member's tick max-age of its clock. Subject:
// the reference line's at, as the trace writes it; null when the trace
// could not be read.
const checkTickFresh = "tick-fresh"

// defaultTickMaxAge is how old the reference may be when the flag is not
// set. It must exceed the proxy's --ring-tick (default 5 s) by a margin
// that covers a stalled emitter being noticed rather than a busy one.
const defaultTickMaxAge = 30 * time.Second

// tickFreshFindings is tick-fresh over a boot read under every rule and
// holding a start line: the reference is the newest tick of the boot, or
// the start line while the boot has no tick yet, and it must be within
// maxAge of now in either direction (a reference that far ahead of this
// clock is two clocks that cannot judge each other). Nothing is kept
// across cycles, so a new boot is judged by its own lines from the cycle
// it appears. Zero maxAge means defaultTickMaxAge.
func tickFreshFindings(boot *gtBoot, now time.Time, maxAge time.Duration) []Finding {
	if maxAge <= 0 {
		maxAge = defaultTickMaxAge
	}
	ref := boot.Records[0].At
	for i := len(boot.Records) - 1; i > 0; i-- {
		if boot.Records[i].Kind == "tick" {
			ref = boot.Records[i].At
			break
		}
	}
	if now.Sub(ref) > maxAge || ref.Sub(now) > maxAge {
		return []Finding{{Check: checkTickFresh, Subject: ref.UTC().Format(gtTimestampLayout)}}
	}
	return nil
}

// tickFreshUnread is the finding when the trace could not be read: there
// is no reference to judge by, so the check has not passed.
func tickFreshUnread() []Finding {
	return []Finding{{Check: checkTickFresh}}
}

// traceConsistentFindings compares the boot as just read with the memory
// in st and then remembers what was read. It is called only with a boot
// read under every rule; an unreadable trace is trace-readable's finding
// and this check's too (traceConsistentUnread), with the memory untouched
// so that a segment that vanished and returned is still compared.
func traceConsistentFindings(st *State, boot *gtBoot) []Finding {
	if st.TraceSegments == nil || st.TraceBoot != boot.Number {
		st.TraceBoot = boot.Number
		st.TraceSegments = map[string]TraceSegment{}
	}
	present := map[string]*gtSegment{}
	for i := range boot.Segments {
		present[boot.Segments[i].Name] = &boot.Segments[i]
	}
	var out []Finding
	names := make([]string, 0, len(st.TraceSegments))
	for name := range st.TraceSegments {
		names = append(names, name)
	}
	sort.Strings(names)
	inconsistent := map[string]bool{}
	for _, name := range names {
		mem := st.TraceSegments[name]
		seg, ok := present[name]
		if !ok || int64(len(seg.Prefix)) < mem.Length || seg.sumAt(mem.Length) != mem.Hash {
			inconsistent[name] = true
			out = append(out, Finding{Check: checkTraceConsistent, Subject: gtBootName(boot.Number) + "/" + name})
		}
	}
	// Remember what was read, for the segments that were consistent with
	// what was remembered. A segment that shrank or changed keeps its
	// memory, so it is reported every cycle until the boot changes or the
	// bytes that were read are back, not once: what was read is what was
	// read, and the disk does not get to replace it.
	for _, seg := range boot.Segments {
		if inconsistent[seg.Name] {
			continue
		}
		st.TraceSegments[seg.Name] = TraceSegment{Length: int64(len(seg.Prefix)), Hash: seg.sumAt(int64(len(seg.Prefix)))}
	}
	return out
}

// sumAt is the SHA-256 of the first n bytes of the segment's prefix: the
// sum the read took in its one pass when it summed at n (every read sums
// at the prefix's end, and a read resumed from memory at the remembered
// length, which in a healthy cycle is the length this check remembers
// too), or a hash of those bytes now. Either way it is the SHA-256 of
// exactly those bytes.
func (s *gtSegment) sumAt(n int64) string {
	if v, ok := s.Sums[n]; ok {
		return v
	}
	return hashPrefix(s.Prefix[:n])
}

// traceReadCurrent is a cycle's one read of the proxy's trace: the root
// listed once (the listing is returned for boot-ambiguous, which judges
// the same listing), and the current boot read under every rule, resuming
// the decode from what this member decoded of the same bytes last cycle
// (State.TraceDecode, gtDecodeMemory). What comes back is, record for
// record, what gtReadLatest returns; the memory only spares the decode of
// lines whose bytes are proven unchanged by their hash.
func traceReadCurrent(st *State, root string) (*gtBoot, *gtRoot, error) {
	if st.TraceDecode == nil {
		st.TraceDecode = &gtDecodeMemory{}
	}
	listing := gtListRoot(root)
	boot, err := gtReadLatestFrom(root, listing, st.TraceDecode)
	return boot, listing, err
}

// traceConsistentUnread is the finding when the trace could not be read:
// the check could not run, so it has not passed.
func traceConsistentUnread() []Finding {
	return []Finding{{Check: checkTraceConsistent}}
}

func hashPrefix(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// checkBootEnded is the identifier of the judgement of a boot that ended
// (SPEC 14.3). The readers judge the highest boot, so the moment the proxy
// restarts the boot that just ended leaves every member's view: a process
// the watchdog aborted mid-connection, a torn last line, a boot with no
// shutdown line at all, left a tail nobody read. Subjects, the boot being
// the one that ended: <boot>:unreadable, <boot>:aborted, <boot>:torn,
// <boot>:conn:<id>, <boot>:accept-error:<text>.
const checkBootEnded = "boot-ended"

// bootEndedSubjectBytes bounds the error text in an accept-error subject,
// as accept-loop bounds its own.
const bootEndedSubjectBytes = 64

// bootEndedFindings is boot-ended over one cycle whose read of the trace
// succeeded: current is the boot read under every rule, previous the boot
// this member read the cycle before (State.TraceBoot as it stood before
// traceConsistentFindings moved it; 0 on a process's first cycle).
//
// Once means this. A current boot other than previous makes previous
// pending (State.BootsEnded), if it is not pending already. Every pending
// boot that has ended is then judged (judgeEndedBoot) and forgotten, and
// this process never judges it again, whatever later cycles show. Ended:
// the boot's newest complete line is older than tickMaxAge on this clock,
// or it holds no line, or it cannot be read; a pending boot whose newest
// line is younger may still be a second live process writing, which is
// boot-ambiguous's finding and not this one's, and it waits. A pending
// boot that is the current boot again (its successor's directory gone) is
// dropped unjudged: it has not ended. A member that started after the
// restart has no previous boot and judges nothing: the judgement is made
// by the members that saw the boot end, each once, so it halts the ring
// for one cycle set and clears as they publish. Nothing is judged on a
// cycle whose read failed; the caller does not call.
//
// A pending boot is read under every rule at every look, its bytes
// hashed every time; the decode alone resumes from what the last look
// decoded of the same bytes (State.BootEndedDecode, the memory the
// current boot's read uses), so the looks while a boot waits to end
// decode its lines once, not once per cycle. The memory is dropped with
// the last pending boot.
func bootEndedFindings(st *State, root string, previous int64, current *gtBoot, now time.Time, tickMaxAge time.Duration) []Finding {
	if tickMaxAge <= 0 {
		tickMaxAge = defaultTickMaxAge
	}
	if current == nil {
		return nil
	}
	if previous != 0 && previous != current.Number {
		pending := false
		for _, n := range st.BootsEnded {
			if n == previous {
				pending = true
			}
		}
		if !pending {
			st.BootsEnded = append(st.BootsEnded, previous)
		}
	}
	var out []Finding
	var still []int64
	for _, n := range st.BootsEnded {
		if n == current.Number {
			continue
		}
		if st.BootEndedDecode == nil {
			st.BootEndedDecode = &gtDecodeMemory{}
		}
		findings, ended := judgeEndedBoot(root, n, st.BootEndedDecode, now, tickMaxAge)
		if !ended {
			still = append(still, n)
			continue
		}
		out = append(out, findings...)
	}
	st.BootsEnded = still
	if len(still) == 0 {
		st.BootEndedDecode = nil
	}
	return out
}

// judgeEndedBoot reads boot n under every rule of ringtrace/README.md 1.4
// and, when it has ended (bootEndedFindings), judges its tail. In order:
// unreadable when the read fails (the check has not passed); aborted when
// it holds no shutdown line, a shutdown line being how every requested
// stop is recorded, so its absence is a process killed, crashed or
// aborted by the watchdog, or one that died before its first line; torn
// when its last segment ends in a line without a line feed, a write the
// process died inside; conn:<id> for every connection with an accept line
// and no close line, in id order, whether the boot was aborted or its
// drain ran out; and, when aborted, accept-error:<text> once per distinct
// error text (bounded) of the accept-error lines within tickMaxAge before
// the boot's newest line, the failed accepts that preceded the abort,
// which accept-loop never saw because the boot was gone. Nothing else of
// the boot is judged again: its decisions, material and status surface
// were judged while it was current. mem is the decode memory of the last
// look (bootEndedFindings), nil to decode every line.
func judgeEndedBoot(root string, n int64, mem *gtDecodeMemory, now time.Time, tickMaxAge time.Duration) ([]Finding, bool) {
	name := gtBootName(n)
	fail := func(out []Finding, subject string) []Finding {
		return append(out, Finding{Check: checkBootEnded, Subject: name + ":" + subject})
	}
	b, err := gtReadBoot(root, n, mem)
	if err != nil {
		return fail(nil, "unreadable"), true
	}
	if len(b.Records) > 0 && now.Sub(b.Records[len(b.Records)-1].At) <= tickMaxAge {
		return nil, false
	}
	var out []Finding
	aborted := true
	for i := range b.Records {
		if b.Records[i].Kind == "shutdown" {
			aborted = false
			break
		}
	}
	if aborted {
		out = fail(out, "aborted")
	}
	if b.Torn {
		out = fail(out, "torn")
	}
	opened := map[int64]bool{}
	closed := map[int64]bool{}
	var order []int64
	for i := range b.Records {
		rec := &b.Records[i]
		switch rec.Kind {
		case "accept":
			if !opened[rec.Accept.Conn] {
				opened[rec.Accept.Conn] = true
				order = append(order, rec.Accept.Conn)
			}
		case "close":
			closed[rec.Close.Conn] = true
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, id := range order {
		if !closed[id] {
			out = fail(out, "conn:"+strconv.FormatInt(id, 10))
		}
	}
	if aborted && len(b.Records) > 0 {
		end := b.Records[len(b.Records)-1].At
		seen := map[string]bool{}
		for i := range b.Records {
			rec := &b.Records[i]
			if rec.Kind != "accept-error" || end.Sub(rec.At) > tickMaxAge {
				continue
			}
			text := boundBytes(rec.AcceptError.Error, bootEndedSubjectBytes)
			if !seen[text] {
				seen[text] = true
				out = fail(out, "accept-error:"+text)
			}
		}
	}
	return out, true
}
