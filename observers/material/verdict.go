package main

// verdict.go implements procedure V (SPEC 8.1): exactly one verdict for each
// subject A in OTHERS, from absent, alive, stale, retired, faulted, unknown.
// The verdict is one thing and findings are another; one read can produce
// both.

import (
	"path"
	"path/filepath"
	"time"
)

// staleAfter is STALE_AFTER_SECONDS(A) = A.cadence_seconds * (1 + STALE_SLACK)
// (SPEC 8), a duration on the reader's own clock.
func (r *reader) staleAfter(cur *Heartbeat) time.Duration {
	return time.Duration(float64(cur.CadenceSeconds) * (1 + r.cfg.StaleSlack) * float64(time.Second))
}

// verdictFor runs SPEC 13 step 4 for one subject: the store-root shape check
// (11.2) and then procedure V. It records the verdict, observed[A], the
// subject's chain (for I1(b)) and every finding.
func (r *reader) verdictFor(A string) {
	storeDisk := r.storePath(A)

	// V1 readable. The root listing also feeds the shape check.
	des, err := r.list(storeDisk)
	if err != nil {
		r.verdicts[A] = VerdictUnknown
		r.fail("store-readable", A)
		r.observed[A] = nil
		return
	}
	r.checkRootShape(A, des)

	// V2 present.
	hbDisk := filepath.Join(storeDisk, "heartbeat")
	info, err := r.stat(hbDisk)
	folderExists := err == nil && info.IsDir()
	hasEntries := false
	if folderExists {
		if hbEntries, err := r.list(hbDisk); err == nil {
			for _, de := range hbEntries {
				if reHeartbeatName.MatchString(de.Name()) {
					hasEntries = true
					break
				}
			}
		}
	}
	if !hasEntries {
		if r.st.HasBasis && r.st.Basis[A] != nil {
			// The folder or its entries existed when R last looked.
			if !folderExists {
				r.fail("I4", A)
			} else {
				r.fail("I1", A)
			}
		}
		r.fail("member-present", A)
		r.verdicts[A] = VerdictAbsent
		r.observed[A] = nil
		return
	}

	// V3 chain.
	res := r.runC(hbDisk, path.Join(A, "heartbeat"), A)
	r.entries[A] = res
	if res.Highest == nil || !res.Highest.Parsed {
		r.verdicts[A] = VerdictUnknown
		r.observed[A] = nil
		return
	}
	cur := res.Highest.HB
	h := res.Highest.Hash
	r.cur[A] = cur
	r.observed[A] = &h

	// V4 retired: a member that has stopped is not verifying the stores.
	if cur.Stop {
		r.verdicts[A] = VerdictRetired
		r.fail("member-fresh", A)
		return
	}

	// V4b the absolute backstop: the one verdict that reads a timestamp.
	// It reads it in both directions. A heartbeat ahead of the reader's
	// clock by more than the limit is a clock that disagrees, and a clock
	// that disagrees disagrees whichever way it runs; the gate refuses the
	// coordinator's on the same rule (SPEC 19.3), and a member that
	// accepted what the gate refuses would report a healthy ring around a
	// proxy that serves nothing.
	if r.cfg.HeartbeatMaxAge > 0 {
		ts, err := parseTimestamp(cur.Timestamp)
		if err != nil || r.cfg.Now.Sub(ts) > r.cfg.HeartbeatMaxAge || ts.Sub(r.cfg.Now) > r.cfg.HeartbeatMaxAge {
			r.verdicts[A] = VerdictStale
			r.fail("member-fresh", A)
			return
		}
	}

	// V5 no basis.
	if !r.st.HasBasis || r.st.Basis[A] == nil {
		if r.faultAtRoot(A) {
			r.verdicts[A] = VerdictFaulted
		} else {
			r.verdicts[A] = VerdictUnknown
		}
		return
	}
	H := *r.st.Basis[A]

	if H == h {
		// V6 unchanged.
		if r.st.Unchanged[A] >= r.staleAfter(cur) {
			r.verdicts[A] = VerdictStale
			r.fail("member-fresh", A)
			return
		}
	} else if !res.Hashes[H] {
		// V7 advanced, but the record is nowhere in the chain: a lie, or
		// a member more than a window behind; both are treated the same.
		r.fail("I1", A)
		r.verdicts[A] = VerdictUnknown
		return
	}

	// V8 faulted or alive.
	if r.faultAtRoot(A) {
		r.verdicts[A] = VerdictFaulted
	} else {
		r.verdicts[A] = VerdictAlive
	}
}

// faultRead is a store's root fault as read this cycle.
type faultRead struct {
	Present bool
	// Bytes are the file's bytes when it was within bound and readable.
	Bytes []byte
	// Parsed is the fault those bytes parse to, when they parse and it
	// names the store as its observer; nil otherwise. Kept so that the
	// peer views (cycle.go) carry the parse V8 made rather than a second
	// parse of the same bytes.
	Parsed *Fault
}

// faultAtRoot reports whether <store>/fault exists, reading and checking it
// once per cycle: a fault is a fault by presence, and one that is oversized,
// misplaced-heartbeat, or malformed additionally fires S4, I6 or S5 with the
// file's path (SPEC 8.1 V8, 3.1).
func (r *reader) faultAtRoot(store string) bool {
	if fr, ok := r.faults[store]; ok {
		return fr.Present
	}
	fr := &faultRead{}
	r.faults[store] = fr
	disk := r.storePath(store, "fault")
	sub := path.Join(store, "fault")
	info, err := r.stat(disk)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	fr.Present = true
	data, oversized, err := r.readWithin(disk, r.cfg.MaxFaultBytes)
	if oversized {
		r.fail("S4", sub)
		return true
	}
	if err != nil {
		r.fail("S5", sub)
		return true
	}
	fr.Bytes = data
	if classify(data) == KindHeartbeat {
		r.fail("I6", sub)
		return true
	}
	f, err := parseFault(data)
	if err != nil || f.Observer != store {
		r.fail("S5", sub)
		return true
	}
	fr.Parsed = f
	return true
}
