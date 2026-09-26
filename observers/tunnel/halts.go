package main

// halts.go implements SPEC 10 and 12: the in-force rule (10.1), procedure H
// over the owner's own halts/ (10.2, its owner clause H7 over the mapping
// -slot-owners gives), and the raise, relay and clear decisions (12.1,
// 12.2, 12.3) computed as what the reader would write.

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// haltFound is the first halt in force found on the 12.2 walk.
type haltFound struct {
	Rel   string
	Bytes []byte
}

// haltInForce is SPEC 10.1: a halt is in force when any store holds a regular
// file named halt at its root, or a regular file inside halts/ whose name does
// not end in .tmp. Existence, not content. It also returns the first halt
// found on the walk of SPEC 12.2 (own halt, own halts/ by writer, then each
// other store's halt and halts/ in identity order), whose bytes a relay
// copies; a found file too large to read within MAX_HALT_BYTES is in force
// but is not relayed, and the walk goes on to the next.
func (r *reader) haltInForce() (bool, *haltFound) {
	inForce := false
	var first *haltFound
	note := func(rel, disk string) {
		inForce = true
		if first != nil {
			return
		}
		data, oversized, err := r.readWithin(disk, r.cfg.MaxHaltBytes)
		if oversized || err != nil {
			r.logf("halt in force at %s could not be read within bound; not relayed", rel)
			return
		}
		first = &haltFound{Rel: rel, Bytes: data}
	}
	stores := append([]string{r.cfg.Identity}, r.others...)
	for _, s := range stores {
		if info, err := r.stat(r.storePath(s, "halt")); err == nil && info.Mode().IsRegular() {
			note(path.Join(s, "halt"), r.storePath(s, "halt"))
		}
		des, err := r.list(r.storePath(s, "halts"))
		if err != nil {
			continue
		}
		for _, de := range des {
			if !de.Type().IsRegular() || strings.HasSuffix(de.Name(), ".tmp") {
				continue
			}
			note(path.Join(s, "halts", de.Name()), r.storePath(s, "halts", de.Name()))
		}
	}
	return inForce, first
}

// runH is procedure H (SPEC 10.2): the owner validates its own halts/ every
// cycle, before it acts on anything found there. The permitted writers are
// OTHERS.
func (r *reader) runH() {
	self := r.cfg.Identity
	disk := r.storePath(self, "halts")
	relDir := path.Join(self, "halts")

	// H1 readable.
	des, err := r.list(disk)
	if err != nil {
		r.fail("halts-readable", "")
		return
	}
	writers := make(map[string]bool, len(r.others))
	for _, w := range r.others {
		writers[w] = true
	}

	// H2 names. named keeps every entry that passes, slot or staging file,
	// in listing order, for H7.
	var slots, staging, named []string
	for _, de := range des {
		name := de.Name()
		sub := path.Join(relDir, name)
		full := filepath.Join(disk, name)
		if de.IsDir() {
			r.fail("S2", sub)
			continue
		}
		w := strings.TrimSuffix(name, ".tmp")
		if !writers[w] || !de.Type().IsRegular() {
			r.failStray(full, sub)
			continue
		}
		named = append(named, name)
		if w != name {
			staging = append(staging, name)
		} else {
			slots = append(slots, name)
		}
	}
	// H3 counts: one <w>.tmp per writer is what the naming rule gives; a
	// filesystem cannot present two entries of one name.

	// H4 staging age.
	for _, name := range staging {
		if r.stagingStale(filepath.Join(disk, name)) {
			r.fail("staging-fresh", path.Join(relDir, name))
		}
	}

	// H5 sizes and H6 parse.
	for _, name := range slots {
		sub := path.Join(relDir, name)
		data, oversized, err := r.readWithin(filepath.Join(disk, name), r.cfg.MaxHaltBytes)
		if oversized {
			r.fail("S4", sub)
			continue
		}
		if err != nil {
			r.fail("S5", sub)
			continue
		}
		if classify(data) == KindHeartbeat {
			r.fail("I6", sub)
			continue
		}
		if _, err := parseHalt(data); err != nil {
			r.fail("S5", sub)
		}
	}

	// H7 owner. The kernel records who created each entry. Every entry
	// named for a writer w, the slot and its staging file, must be owned
	// by the account w runs as; one created by anyone else under w's name
	// is I8, with the file and what was found as its subject. The mapping
	// is -slot-owners; without one (the fixture harness, whose trees carry
	// no ownership) the clause is not evaluated.
	if r.cfg.SlotOwners == nil {
		return
	}
	for _, name := range named {
		full := filepath.Join(disk, name)
		owner := func() (uint32, error) {
			info, err := r.stat(full)
			if err != nil {
				if isGone(full, err) {
					return 0, errSlotGone
				}
				return 0, err
			}
			return fileOwnerUID(info)
		}
		if s := slotOwnerSubject(path.Join(relDir, name), strings.TrimSuffix(name, ".tmp"), r.cfg.SlotOwners, runtime.GOOS, lookupUID, owner); s != "" {
			r.fail("I8", s)
		}
	}
}

// errSlotGone is what the owner probe of H7 returns for an entry the
// listing held and a stat now shows gone (isGone): its writer cleared it
// between the two.
var errSlotGone = errors.New("slot gone since the listing")

// slotOwnerSubject is the rule of H7 (SPEC 10.2) for one entry of the own
// halts/ named for the writer w, the slot <w> or its staging file <w>.tmp,
// at rel: "" when the entry is owned by the account owners names for w,
// else the subject I8 fires with, the entry's path and then what was found.
//
//	goos not linux                         -> <rel>:unsupported-os:<goos>
//	owners names no account for w          -> <rel>:unmapped
//	the account cannot be resolved         -> <rel>:no-account:<name>
//	the entry cannot be stat'ed            -> <rel>:unprobed
//	the owning uid is not the account's    -> <rel>:owner:<uid>
//
// An entry shown gone between the listing and the stat (errSlotGone) is
// its writer clearing it, which is no finding: the next cycle's listing
// judges what is there then. Every other failure to know the owner fails
// closed, since an entry whose owner cannot be known has not been shown
// to be its writer's. On an OS without POSIX ownership nothing can be
// known, so any entry at all fails; an empty halts/ has no entry and
// reads clean.
func slotOwnerSubject(rel, w string, owners map[string]string, goos string, uidOf idLookup, owner func() (uint32, error)) string {
	if goos != "linux" {
		return rel + ":unsupported-os:" + goos
	}
	account, ok := owners[w]
	if !ok || account == "" {
		return rel + ":unmapped"
	}
	want, err := uidOf(account)
	if err != nil {
		return rel + ":no-account:" + account
	}
	got, err := owner()
	if errors.Is(err, errSlotGone) {
		return ""
	}
	if err != nil {
		return rel + ":unprobed"
	}
	if got != want {
		return fmt.Sprintf("%s:owner:%d", rel, got)
	}
	return ""
}

// parseSlotOwners parses -slot-owners, member=account pairs separated by
// commas, into the mapping of SPEC 10.2 H7. Every declared member must be
// named exactly once, with a non-empty account, and nothing else may be:
// the mapping is the deployment's statement of who runs as what, and an
// incomplete or contradictory one is a configuration the member refuses
// to start on, as it refuses a heartbeat-max-age at or below its cadence.
func parseSlotOwners(s string, members []string) (map[string]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("slot-owners must name the account of every member, as member=account pairs")
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("slot-owners: bad pair %q", pair)
		}
		member := false
		for _, m := range members {
			if m == kv[0] {
				member = true
			}
		}
		if !member {
			return nil, fmt.Errorf("slot-owners: %q is not a declared member", kv[0])
		}
		if _, dup := out[kv[0]]; dup {
			return nil, fmt.Errorf("slot-owners: %s named twice", kv[0])
		}
		out[kv[0]] = kv[1]
	}
	for _, m := range members {
		if _, ok := out[m]; !ok {
			return nil, fmt.Errorf("slot-owners: no account for member %q", m)
		}
	}
	return out, nil
}

// decideHalts is SPEC 13 step 11: raise (12.1) if anything failed; otherwise
// evaluate the clear-condition and either clear (12.3) or relay (12.2).
func (r *reader) decideHalts(out *Outcome, inForce bool, found *haltFound) {
	self := r.cfg.Identity
	coord := r.cfg.Coordinator
	isCoord := self == coord

	if len(r.findings) > 0 {
		// 12.1 raise: the halt names the first failing assertion.
		first := r.findings[0]
		h := &Halt{
			Observer: self,
			Reason:   first.Check,
			Subject:  first.SubjectPtr(),
			Sequence: out.Publish.Sequence,
			When:     formatTimestamp(r.cfg.Now),
			Detail:   fmt.Sprintf("%s found %s failing (%d assertion(s) failing this cycle)", self, describe(first), len(r.findings)),
		}
		b, err := encodeHalt(h)
		if err != nil {
			// A halt that cannot be encoded is a programming error; the
			// presence is the signal, so write the reason as plain text.
			b = []byte(fmt.Sprintf("%s %s\n", first.Check, first.Subject))
		}
		out.Halt = HaltDecision{Writes: true, Reason: first.Check, Subject: first.Subject, Bytes: b}
		out.Halt.OwnHaltWritten = !r.existsNow(self, "halt")
		var order []string
		if !isCoord && coord != "" {
			order = append(order, coord)
		}
		for _, s := range r.others {
			if s != coord || isCoord {
				order = append(order, s)
			}
		}
		for _, s := range order {
			if !r.existsNow(s, "halts", self) {
				out.Halt.Slots = append(out.Halt.Slots, s)
			}
		}
		r.logf("halt raised: %s subject %s; slots written in %v", first.Check, subjectText(first.Subject), out.Halt.Slots)
		return
	}

	// 12.3 the clear-condition: no fault at the root of any store; for a
	// member, the coordinator's own halt absent; own assertions passed.
	clear := true
	for _, s := range r.cfg.Members {
		if r.existsNow(s, "fault") {
			clear = false
			break
		}
	}
	if clear && !isCoord && coord != "" && r.existsNow(coord, "halt") {
		clear = false
	}
	if clear {
		out.Clears = &ClearDecision{Removes: []string{}}
		var order []string
		for i := len(r.others) - 1; i >= 0; i-- {
			if s := r.others[i]; s != coord || isCoord {
				order = append(order, s)
			}
		}
		if !isCoord && coord != "" {
			order = append(order, coord)
		}
		for _, s := range order {
			if r.existsNow(s, "halts", self) {
				out.Clears.Removes = append(out.Clears.Removes, path.Join(s, "halts", self))
			}
		}
		if r.existsNow(self, "halt") {
			out.Clears.Removes = append(out.Clears.Removes, path.Join(self, "halt"))
		}
		if len(out.Clears.Removes) > 0 {
			r.logf("clear-condition holds; removing %v", out.Clears.Removes)
		}
		return
	}

	// 12.2 relay: a halt spreads by being received. Never overwrites.
	if !inForce {
		return
	}
	out.Relay.Active = true
	for _, s := range r.others {
		if r.existsNow(s, "halts", self) {
			out.Relay.Leaves = append(out.Relay.Leaves, s)
		} else {
			out.Relay.Writes = append(out.Relay.Writes, s)
		}
	}
	if found != nil {
		out.Relay.Bytes = found.Bytes
		out.Relay.From = found.Rel
	} else {
		// Every halt in force was beyond bound; nothing can be copied.
		out.Relay.Writes = nil
	}
	if len(out.Relay.Writes) > 0 {
		r.logf("relaying halt found at %s into %v", out.Relay.From, out.Relay.Writes)
	}
}

func describe(f Finding) string {
	return f.Check + " on " + subjectText(f.Subject)
}

func subjectText(s string) string {
	if s == "" {
		return "null"
	}
	return s
}
