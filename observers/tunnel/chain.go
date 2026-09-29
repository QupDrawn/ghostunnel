package main

// chain.go implements procedure C (SPEC 6.1): is a heartbeat folder a
// well-formed chain? It runs over a member's own folder (by every reader,
// including the owner) and over every copy of it. Every step runs and every
// finding is collected; the first finding in step order is what a halt names.

import (
	"os"
	"path"
	"path/filepath"
	"strings"
)

// chainEntry is one <seq>.hb entry of a folder as read this cycle.
type chainEntry struct {
	Name string
	Seq  int64
	Rel  string // subject form, <store>/<path>
	Disk string
	// Read is true when the bytes were read (not oversized, not unreadable);
	// Hash is then SHA-256 over those bytes (SPEC 3.5).
	Read  bool
	Bytes []byte
	Hash  string
	// Parsed is true when the entry passed C5; HB is then its content.
	Parsed bool
	HB     *Heartbeat
}

// chainResult is what procedure C found in one folder.
type chainResult struct {
	// Exists is false when the folder could not be listed.
	Exists bool
	// Entries are the heartbeat entries in name order, parsed or not.
	Entries []*chainEntry
	// Staging names the staging files present.
	Staging []string
	// Highest is the last entry by name, or nil when there is none.
	Highest *chainEntry
	// Hashes holds the hash of every entry whose bytes were read.
	Hashes map[string]bool
}

// bySequence indexes the entries by sequence.
func (c *chainResult) bySequence() map[int64]*chainEntry {
	m := make(map[int64]*chainEntry, len(c.Entries))
	for _, e := range c.Entries {
		m[e.Seq] = e
	}
	return m
}

// readEntry reads one heartbeat entry within bound. It is a variable, and
// only so that a test can act between the listing and the read: that gap is
// where the prune race lives, and no state on disk can stand in for it.
var readEntry = readBounded

// runC runs procedure C over the folder at disk, whose subject form is
// relDir, said to belong to author. A folder that cannot be listed yields
// Exists false and no finding: the caller knows what that means at its place
// (V2 for a member's folder, K3 for a copy).
func (r *reader) runC(disk, relDir, author string) *chainResult {
	res := &chainResult{Hashes: map[string]bool{}}
	des, err := r.list(disk)
	if err != nil {
		return res
	}
	res.Exists = true

	// C1 names. os.ReadDir lists in name order, which is sequence order.
	for _, de := range des {
		name := de.Name()
		sub := path.Join(relDir, name)
		full := filepath.Join(disk, name)
		switch {
		case de.IsDir():
			r.fail("S2", sub)
		case !de.Type().IsRegular():
			r.fail("S1", sub)
		case reHeartbeatName.MatchString(name):
			res.Entries = append(res.Entries, &chainEntry{Name: name, Seq: sequenceOfName(name), Rel: sub, Disk: full})
		case reStagingName.MatchString(name):
			res.Staging = append(res.Staging, name)
		default:
			if classify(readPrefix(full)) == KindHeartbeat {
				r.fail("I6", sub)
			} else {
				r.fail("S1", sub)
			}
		}
	}

	// C2 counts.
	if len(res.Entries) > r.cfg.Window+1 {
		r.fail("S3", relDir)
	}
	if len(res.Staging) > 1 {
		r.fail("S3", relDir)
	}

	// C3 staging age, by modification time against the reader's clock.
	for _, name := range res.Staging {
		if r.stagingStale(filepath.Join(disk, name)) {
			r.fail("staging-fresh", path.Join(relDir, name))
		}
	}

	// C4 sizes, then C5 parse, entry by entry.
	for _, e := range res.Entries {
		data, oversized, err := r.readWithin(e.Disk, r.cfg.MaxHeartbeatBytes)
		if oversized {
			r.fail("S4", e.Rel)
			continue
		}
		if err != nil {
			// The owner prunes its own folder every cycle, so an entry gone
			// between the listing and the read is the ordinary race and not
			// a malformed file: it stays a listed name (it counts for C2 and
			// C6) with nothing read and nothing parsed, and there is no
			// finding. Calling it S5 would be a compromise fired by a benign
			// event, which is the one thing the compromise set must never
			// do. An entry still present and still unreadable is another
			// matter. "Gone" means shown gone: the read failed with
			// not-exist, or an Lstat now fails with not-exist. "Still
			// present" is everything else: an Lstat that succeeds, whatever
			// it finds under the name, and an Lstat that fails for any
			// other reason, since an entry that cannot be shown gone has
			// not been shown benign.
			if isGone(e.Disk, err) {
				continue
			}
			r.fail("S5", e.Rel)
			continue
		}
		e.Read = true
		e.Bytes = data
		e.Hash = r.hashOf(e.Disk, data)
		res.Hashes[e.Hash] = true
		hb, err := r.parseEntry(data, e.Hash)
		if err != nil || hb.Observer != author || hb.Sequence != e.Seq {
			r.fail("S5", e.Rel)
			continue
		}
		e.Parsed = true
		e.HB = hb
		if hb.CheckCount != int64(len(hb.Checks)) || hasDuplicate(hb.Checks) {
			r.fail("I2", author)
		}
	}

	// C6 consecutive: the names, sorted, form a run with no gap.
	for i := 1; i < len(res.Entries); i++ {
		if res.Entries[i].Seq != res.Entries[i-1].Seq+1 {
			r.fail("I3", author)
			break
		}
	}

	// C7 chained.
	bySeq := res.bySequence()
	for _, e := range res.Entries {
		if !e.Parsed {
			continue
		}
		p, present := bySeq[e.Seq-1]
		switch {
		case present && p.Read:
			if e.HB.Previous == nil || *e.HB.Previous != p.Hash {
				r.fail("I3", author)
			}
		case present:
			// The predecessor is there but its bytes could not be read
			// (oversized or unreadable); its own finding stands and the
			// link cannot be checked.
		case e.Seq == 1:
			if e.HB.Previous != nil {
				r.fail("I3", author)
			}
		default:
			// Predecessor pruned: a non-null value cannot be checked and is
			// accepted; a null above sequence 1 is a restarted chain.
			if e.HB.Previous == nil {
				r.fail("I3", author)
			}
		}
	}

	// C8 boot records.
	for _, e := range res.Entries {
		if !e.Parsed || e.HB.Boot == nil {
			continue
		}
		rf := e.HB.Boot.ResumedFrom
		if e.Seq > 1 {
			if rf == nil || *rf != e.Seq-1 {
				r.fail("I3", author)
			}
		} else if rf != nil {
			r.fail("I3", author)
		}
	}

	// C9 stops.
	for _, e := range res.Entries {
		if !e.Parsed || !e.HB.Stop {
			continue
		}
		if s, ok := bySeq[e.Seq+1]; ok && s.Parsed && s.HB.Boot == nil {
			r.fail("I3", author)
		}
	}

	if n := len(res.Entries); n > 0 {
		res.Highest = res.Entries[n-1]
	}
	return res
}

// parseMemory is the strict parse (C5) of every heartbeat entry read this
// cycle and, until this cycle ends, last cycle: the result, error included,
// keyed by the SHA-256 of the bytes and the declared membership, which are
// the parse's only inputs. Identical bytes parse to an identical result, so
// a parse remembered under a hash is the parse of any bytes that hash the
// same, under the collision resistance the chain links already rest on
// (C7). The bytes are still read and hashed every cycle; what the memory
// spares is the parse. The comparisons that depend on the entry's place
// (the author against the folder, the sequence against the name) run on
// every entry every cycle. A remembered *Heartbeat is never written to by
// its readers.
//
// It is bounded by what a cycle reads: at the end of a cycle every entry
// not seen in it is forgotten.
type parseMemory struct {
	gen     uint64
	entries map[string]*parsedEntry
}

type parsedEntry struct {
	hb   *Heartbeat
	err  error
	seen uint64
}

// begin starts a cycle.
func (m *parseMemory) begin() {
	m.gen++
	if m.entries == nil {
		m.entries = map[string]*parsedEntry{}
	}
}

// end forgets every entry the cycle did not see.
func (m *parseMemory) end() {
	for k, e := range m.entries {
		if e.seen != m.gen {
			delete(m.entries, k)
		}
	}
}

// holds reports whether a parse is remembered under hash, for any
// membership.
func (m *parseMemory) holds(hash string) bool {
	for k := range m.entries {
		if strings.HasPrefix(k, hash+"\x00") {
			return true
		}
	}
	return false
}

// parseEntryBytes is C5's strict parse. It is a variable only so that a
// test can count the parses a cycle makes.
var parseEntryBytes = parseHeartbeat

// parseEntry is C5's strict parse of one entry's bytes, whose SHA-256 is
// hash, under the declared membership: the parse remembered under that
// hash and membership, or a parse now, remembered.
func (r *reader) parseEntry(data []byte, hash string) (*Heartbeat, error) {
	key := hash + "\x00" + r.membership
	if e, ok := r.parses.entries[key]; ok {
		e.seen = r.parses.gen
		return e.hb, e.err
	}
	hb, err := parseEntryBytes(data, r.cfg.Members)
	r.parses.entries[key] = &parsedEntry{hb: hb, err: err, seen: r.parses.gen}
	return hb, err
}

// hasDuplicate reports whether any identifier appears twice.
func hasDuplicate(ids []string) bool {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

// isGone reports whether the entry at disk, whose read failed with err, has
// been shown gone: the read itself said not-exist, or an Lstat now does.
// The Lstat is of the disk now and not of the cycle's snapshot (cycle.go):
// it asks what became of the entry after the read, which nothing seen
// before the read can answer. Not a method of the reader, so that it
// cannot be served.
func isGone(disk string, err error) bool {
	if os.IsNotExist(err) {
		return true
	}
	_, err = os.Lstat(disk)
	return os.IsNotExist(err)
}

// stagingStale reports whether the staging file at disk is older than
// STAGING_STALE_AFTER_SECONDS by its modification time (SPEC C3, K2, H4).
// A staging file that cannot be stat'ed is not judged. The check exists to
// catch a writer that crashed between create and rename, and that writer's
// staging file persists and can be stat'ed for as long as it matters; a
// staging file that vanished between the listing and the stat was renamed
// into place by a writer that is alive, which is the fresh case, not the
// stale one. The stat is of the disk now, not of the cycle's snapshot
// (cycle.go), for the same reason: it is the state after the listing that
// tells the two cases apart.
func (r *reader) stagingStale(disk string) bool {
	info, err := os.Lstat(disk)
	if err != nil {
		return false
	}
	return info.ModTime().Before(r.cfg.Now.Add(-r.cfg.StagingStaleAfter))
}
