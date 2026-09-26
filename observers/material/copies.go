package main

// copies.go implements procedure K (SPEC 9): the receiver validates the shape
// of a copy directory before it looks at the content, then compares the
// content against the author's own store as the member pass listed and read
// it at step 4 (the own folder at step 3), before the copy. The copy is read
// after the original, so it can be behind and can be one entry ahead of a
// ceiling that went stale between the two steps; behind is K6, and ahead is
// settled by listing the original again, now.

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"sort"
)

// copyDir names one copy directory: the store it sits in, its directory name
// and the member that writes it.
type copyDir struct {
	Store  string
	Dir    string
	Author string
}

// copyDirsOf lists the copy directories a store holds, from the declared
// copy cycle: an application store holds copy/ (written by its author) and
// copy-<coordinator>/; the coordinator's store holds copy-<m>/ for every
// other member. This is also the set of directories permitted at that root
// (SPEC 11.2).
func (r *reader) copyDirsOf(store string) []copyDir {
	var out []copyDir
	if store == r.cfg.Coordinator {
		for _, m := range r.cfg.Members {
			if m != store {
				out = append(out, copyDir{Store: store, Dir: "copy-" + m, Author: m})
			}
		}
	} else {
		if author, ok := r.cfg.CopyAuthor[store]; ok {
			out = append(out, copyDir{Store: store, Dir: "copy", Author: author})
		}
		if r.cfg.Coordinator != "" {
			out = append(out, copyDir{Store: store, Dir: "copy-" + r.cfg.Coordinator, Author: r.cfg.Coordinator})
		}
	}
	return out
}

// copiesToValidate lists the copy directories this reader runs K over, in
// identity order of author (SPEC 13 step 5): every copy in its own store,
// and, for the coordinator, every application store's copy/ as well (the
// whole-view comparison of SPEC 9).
func (r *reader) copiesToValidate() []copyDir {
	dirs := r.copyDirsOf(r.cfg.Identity)
	if r.cfg.Identity == r.cfg.Coordinator {
		for _, s := range r.cfg.Members {
			if s == r.cfg.Identity {
				continue
			}
			if author, ok := r.cfg.CopyAuthor[s]; ok {
				dirs = append(dirs, copyDir{Store: s, Dir: "copy", Author: author})
			}
		}
	}
	sort.SliceStable(dirs, func(i, j int) bool {
		if dirs[i].Author != dirs[j].Author {
			return dirs[i].Author < dirs[j].Author
		}
		// Own store first, then the others in identity order.
		if (dirs[i].Store == r.cfg.Identity) != (dirs[j].Store == r.cfg.Identity) {
			return dirs[i].Store == r.cfg.Identity
		}
		return dirs[i].Store < dirs[j].Store
	})
	return dirs
}

// runK runs procedure K over one copy directory.
func (r *reader) runK(cd copyDir) {
	disk := r.storePath(cd.Store, cd.Dir)
	relDir := path.Join(cd.Store, cd.Dir)
	author := cd.Author

	// K1 readable.
	des, err := r.list(disk)
	if err != nil {
		r.fail("copy-readable", author)
		return
	}

	// K2 root shape. The copy's fault is read here, once, for K7.
	var (
		hbDirExists  bool
		faultPresent bool
		faultUnread  bool // oversized or unreadable: K7 does not run
		faultData    []byte
	)
	for _, de := range des {
		name := de.Name()
		sub := path.Join(relDir, name)
		full := filepath.Join(disk, name)
		switch name {
		case "heartbeat":
			if de.IsDir() {
				hbDirExists = true
			} else {
				r.failStray(full, sub)
			}
		case "fault":
			if de.IsDir() {
				r.fail("S2", sub)
				continue
			}
			faultPresent = true
			data, oversized, err := r.readWithin(full, r.cfg.MaxFaultBytes)
			if oversized {
				r.fail("S4", sub)
				faultUnread = true
			} else if err != nil {
				r.fail("S5", sub)
				faultUnread = true
			} else {
				faultData = data
			}
		case "fault.tmp":
			if de.IsDir() {
				r.fail("S2", sub)
			} else if r.stagingStale(full) {
				r.fail("staging-fresh", sub)
			}
		default:
			if de.IsDir() {
				r.fail("S2", sub)
			} else {
				r.failStray(full, sub)
			}
		}
	}

	// K3 heartbeat shape.
	var cres *chainResult
	if hbDirExists {
		cres = r.runC(filepath.Join(disk, "heartbeat"), path.Join(relDir, "heartbeat"), author)
	} else {
		cres = &chainResult{Hashes: map[string]bool{}}
	}

	// K4 original: the author's own folder as procedure C listed and read it
	// at step 4 (the own folder at step 3), before this copy. The window is
	// bounded by what that listing showed, not by what could be read: an
	// entry pruned between the listing and the read would otherwise lower
	// the ceiling and make a perfectly good copy look like a record the
	// author never published, a compromise fired by the author doing its
	// own housekeeping. A folder the member pass did not read (the author's
	// store unreadable or its folder empty then) is read now instead.
	W := r.originalOf(author)
	if W == nil || len(W.Names) == 0 {
		return
	}
	minW, maxW := W.Names[0], W.Names[len(W.Names)-1]

	// K5 each copy entry.
	//
	// The ceiling above, listed again, and only if something is above it;
	// -1 until it is needed, so the ordinary case pays for no listing.
	freshMax := int64(-1)
	for _, e := range cres.Entries {
		if !e.Parsed {
			continue
		}
		switch {
		case e.Seq > maxW:
			// Above the ceiling from step 4. The copy is read after the
			// original, and an author publishes to its own store first and
			// to the copy second, which is the order it is required to use;
			// so an author that advances between the two steps leaves an
			// honest copy one entry above a ceiling that is merely out of
			// date. A forged entry is above every ceiling for ever, and a
			// race is above only the stale one: the ceiling is taken again
			// now, and the entry is I7 only if it is still above it.
			if freshMax < 0 {
				freshMax = r.freshCeiling(author, maxW)
			}
			if e.Seq > freshMax {
				r.fail("I7", author)
			}
		default:
			// In the window, or below it (K6). Compared only when the
			// original entry was read: one listed but not read (oversized,
			// or present and unreadable) has its own finding at the author
			// and no bytes to compare with.
			if orig, read := W.Bytes[e.Seq]; read && !bytes.Equal(e.Bytes, orig) {
				r.fail("I7", author)
			}
		}
	}

	// K6 behind: nothing in the window, or something behind alongside
	// entries in the window (an unmaintained copy). The floor is the step-4
	// listing's, and the copy is listed after it. A writer prunes each copy
	// before its own folder (SPEC 13 step 10), so a copy's lowest sequence
	// is never below its original's at any instant, and it only ever rises;
	// hence a copy entry below the floor listed earlier is one the writer's
	// own prune of that copy did not remove, and not a race.
	inWindow, behind := 0, 0
	for _, e := range cres.Entries {
		switch {
		case e.Seq < minW:
			behind++
		case e.Seq <= maxW:
			inWindow++
		}
	}
	if inWindow == 0 || behind > 0 {
		r.fail("copy-current", author)
	}

	// K7 the fault copy.
	if faultUnread {
		return
	}
	origPresent, origBytes := r.faultBytesAtRoot(author)
	sub := path.Join(relDir, "fault")
	switch {
	case faultPresent:
		if classify(faultData) == KindHeartbeat {
			r.fail("I6", sub)
			return
		}
		f, err := parseFault(faultData)
		if err != nil {
			r.fail("S5", sub)
			return
		}
		if f.Observer != author {
			r.fail("I7", author)
			return
		}
		if !origPresent || origBytes == nil || !bytes.Equal(faultData, origBytes) {
			r.fail("copy-current", author)
		}
	case origPresent:
		r.fail("copy-current", author)
	}
}

// failStray classifies a regular file found under a name not permitted at
// its place: I6 if it begins with the heartbeat marker, S1 otherwise (SPEC
// 3.1, 11.1 I6).
func (r *reader) failStray(full, sub string) {
	if classify(readPrefix(full)) == KindHeartbeat {
		r.fail("I6", sub)
	} else {
		r.fail("S1", sub)
	}
}

// original is the author's own heartbeat/ as K4 sees it: every sequence the
// listing showed, in ascending order, and the bytes of each entry that was
// read within bound.
type original struct {
	Names []int64
	Bytes map[int64][]byte
}

// originalOf returns the author's own folder as the member pass read it this
// cycle, or, when that pass did not read it, as readOriginal reads it now.
func (r *reader) originalOf(author string) *original {
	res := r.entries[author]
	if res == nil || !res.Exists {
		return r.readOriginal(author)
	}
	W := &original{Bytes: map[int64][]byte{}}
	for _, e := range res.Entries {
		W.Names = append(W.Names, e.Seq)
		if e.Read {
			W.Bytes[e.Seq] = e.Bytes
		}
	}
	sort.Slice(W.Names, func(i, j int) bool { return W.Names[i] < W.Names[j] })
	return W
}

// readOriginal lists and reads the author's own heartbeat/ (K4), recording
// no finding: the original's own findings belong to procedure V. It returns
// nil when the folder cannot be listed. An entry that cannot be read is a
// listed name without bytes.
func (r *reader) readOriginal(author string) *original {
	disk := r.storePath(author, "heartbeat")
	des, err := r.list(disk)
	if err != nil {
		return nil
	}
	W := &original{Bytes: map[int64][]byte{}}
	for _, de := range des {
		if !reHeartbeatName.MatchString(de.Name()) || de.IsDir() {
			continue
		}
		seq := sequenceOfName(de.Name())
		W.Names = append(W.Names, seq)
		data, oversized, err := r.readWithin(filepath.Join(disk, de.Name()), r.cfg.MaxHeartbeatBytes)
		if !oversized && err == nil {
			W.Bytes[seq] = data
		}
	}
	sort.Slice(W.Names, func(i, j int) bool { return W.Names[i] < W.Names[j] })
	return W
}

// freshCeiling lists the author's own heartbeat/ now, names only, and
// returns the highest sequence listed or ceiling, whichever is higher. A
// folder that cannot be listed now leaves the ceiling where it was. It
// reads the disk and not the cycle's snapshot (cycle.go), because its
// whole point is a listing later than the one step 4 took.
func (r *reader) freshCeiling(author string, ceiling int64) int64 {
	des, err := os.ReadDir(r.storePath(author, "heartbeat"))
	if err != nil {
		return ceiling
	}
	for _, de := range des {
		if de.IsDir() || !reHeartbeatName.MatchString(de.Name()) {
			continue
		}
		if seq := sequenceOfName(de.Name()); seq > ceiling {
			ceiling = seq
		}
	}
	return ceiling
}

// faultBytesAtRoot returns whether <store>/fault exists and its bytes when
// they could be read within bound, without recording findings: the
// original's own findings belong to procedure V.
func (r *reader) faultBytesAtRoot(store string) (bool, []byte) {
	if fr, ok := r.faults[store]; ok {
		return fr.Present, fr.Bytes
	}
	disk := r.storePath(store, "fault")
	info, err := r.stat(disk)
	if err != nil || !info.Mode().IsRegular() {
		return false, nil
	}
	data, oversized, err := r.readWithin(disk, r.cfg.MaxFaultBytes)
	if oversized || err != nil {
		return true, nil
	}
	return true, data
}
