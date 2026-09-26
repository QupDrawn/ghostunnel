package main

// invariants.go holds the store-root shape check (SPEC 11.2) and the
// invariants that are not embedded in procedures C, V, K and H: I5 (the
// owner's own files against memory), the owner side of I3, and I1(b) (third
// party accounts). I2, I3 (reader side), I4, I6 and I7 live in the procedures
// that find them.

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// checkRootShape is SPEC 11.2 over one store root. Permitted entries are
// heartbeat (directory), fault, fault.tmp, halt, halt.tmp, halts (directory),
// since and since.tmp (the owner's record of when it first ran, written once
// through its staging file; see writeObservingSinceOnce), and the copy
// directories the declared copy cycle gives that store. An absent since is
// not a shape finding; observing-since reports the owner's own.
func (r *reader) checkRootShape(store string, des []os.DirEntry) {
	dirs := map[string]bool{"heartbeat": true, "halts": true}
	for _, cd := range r.copyDirsOf(store) {
		dirs[cd.Dir] = true
	}
	files := map[string]bool{
		"fault": true, "fault.tmp": true,
		"halt": true, "halt.tmp": true,
		observingSinceName: true, observingSinceName + ".tmp": true,
	}
	for _, de := range des {
		name := de.Name()
		sub := path.Join(store, name)
		full := r.storePath(store, name)
		switch {
		case de.IsDir():
			if !dirs[name] {
				r.fail("S2", sub)
			}
		case files[name] && de.Type().IsRegular():
			// permitted
		default:
			// A permitted file name that is not a regular file, a directory
			// name present as a file, or a name permitted nowhere.
			r.failStray(full, sub)
		}
	}
}

// checkI5 is SPEC 11.1 I5: for every path in memory, the file must exist and
// hash to what memory holds; and a fault or halt in the own store that memory
// does not hold was written by someone else. The same "exists but not in
// memory" form is applied to the own heartbeat folder: an entry the owner
// never wrote is not what it last wrote either, and no benign event puts one
// there (the owner rebuilds memory from the folder on start, SPEC 7).
func (r *reader) checkI5() {
	self := r.cfg.Identity
	keys := make([]string, 0, len(r.st.Memory))
	for k := range r.st.Memory {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		data, err := r.read(filepath.Join(r.cfg.StoresRoot, filepath.FromSlash(k)))
		if err != nil || sha256Hex(data) != r.st.Memory[k] {
			r.fail("I5", k)
		}
	}
	for _, f := range []string{"fault", "halt"} {
		rel := path.Join(self, f)
		if _, held := r.st.Memory[rel]; !held && r.exists(self, f) {
			r.fail("I5", rel)
		}
	}
	if des, err := r.list(r.storePath(self, "heartbeat")); err == nil {
		for _, de := range des {
			if !reHeartbeatName.MatchString(de.Name()) {
				continue
			}
			rel := path.Join(self, "heartbeat", de.Name())
			if _, held := r.st.Memory[rel]; !held {
				r.fail("I5", rel)
			}
		}
	}
}

// memoryHighest returns the highest own heartbeat sequence memory holds and
// its hash, or 0 when memory holds none.
func (r *reader) memoryHighest() (int64, string) {
	prefix := r.cfg.Identity + "/heartbeat/"
	var best int64
	var hash string
	for k, v := range r.st.Memory {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		name := strings.TrimPrefix(k, prefix)
		if !reHeartbeatName.MatchString(name) {
			continue
		}
		if seq := sequenceOfName(name); seq > best {
			best, hash = seq, v
		}
	}
	return best, hash
}

// checkOwnerI3 is the owner side of SPEC 11.1 I3: memory holds the sequence
// the owner last published; if the highest entry now in its own folder is
// lower, the sequence moved backwards by a hand that is not the owner's.
func (r *reader) checkOwnerI3(own *chainResult) {
	memHighest, _ := r.memoryHighest()
	if memHighest == 0 || own == nil || own.Highest == nil {
		return
	}
	if own.Highest.Seq < memHighest {
		r.fail("I3", r.cfg.Identity)
	}
}

// checkThirdPartyAccounts is SPEC 11.1 I1(b): for each member B whose verdict
// is alive or faulted (a current account), each non-null hash it records for
// a member C whose folder is present with entries must be in C's chain.
func (r *reader) checkThirdPartyAccounts() {
	for _, B := range r.others {
		if v := r.verdicts[B]; v != VerdictAlive && v != VerdictFaulted {
			continue
		}
		cur := r.cur[B]
		if cur == nil {
			continue
		}
		subjects := make([]string, 0, len(cur.Observed))
		for C := range cur.Observed {
			subjects = append(subjects, C)
		}
		sort.Strings(subjects)
		for _, C := range subjects {
			if C == B || cur.Observed[C] == nil {
				continue
			}
			res := r.entries[C]
			if res == nil || !res.Exists || len(res.Entries) == 0 {
				continue
			}
			if !res.Hashes[*cur.Observed[C]] {
				r.fail("I1", B)
			}
		}
	}
}
