package main

// ownstore.go is own-store-private (SPEC 13 step 3, SPEC 15): the own
// store is owned and moded as the deployment's tree says, and this member
// cannot write the halts/ inside it. The tree is deploy/tree.tsv, read once
// on start (readStoreTree) for the rows of the own store; the comparison
// (ownStoreMismatches) is portable and proved on every host over synthetic
// entries; only the collection of the entries (probeOwnStore, in
// ownstore_linux.go) reads a real store, and only Linux has the ownership
// this compares. Elsewhere the check cannot run and fails closed, unless
// the operator started the member with -accept-no-store-check naming this
// very OS, the rule of material's -accept-no-sandbox exactly
// (acceptNoStoreCheckValid, ownStorePrivateSubjects).

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/user"
	"path"
	"strconv"
	"strings"
)

// TreeRow is one directory of the deployment's tree: its owner and group
// by name, and its mode as the twelve permission bits.
type TreeRow struct {
	Owner string
	Group string
	Mode  uint32
}

// StoreTree is the expected ownership of the own store's directories, keyed
// by path relative to /stores/ (SPEC 15: <store>/<path>).
type StoreTree struct {
	Rows map[string]TreeRow
}

// readStoreTree reads the deployment's tree at p and keeps the rows of the
// store identity.
func readStoreTree(p, identity string) (*StoreTree, error) {
	data, err := readFile(p)
	if err != nil {
		return nil, err
	}
	return parseStoreTree(data, identity)
}

// parseStoreTree parses the tree's tab-separated rows (path, owner, group,
// mode; # comments and blank lines ignored) and keeps those under the store
// identity, keyed relative to the tree's stores directory: the row for
// .../stores/<identity>/halts is kept as <identity>/halts. A tree with no
// row for the store root itself is an error: nothing could be compared.
func parseStoreTree(data []byte, identity string) (*StoreTree, error) {
	if identity == "" {
		return nil, errors.New("identity is empty")
	}
	tree := &StoreTree{Rows: map[string]TreeRow{}}
	marker := "/stores/" + identity
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, fmt.Errorf("tree line %d: %d fields, want 4", n, len(fields))
		}
		i := strings.Index(fields[0], marker)
		if i < 0 {
			continue
		}
		rest := fields[0][i+len(marker):]
		if rest != "" && !strings.HasPrefix(rest, "/") {
			continue // another store whose name begins with this identity
		}
		mode, err := strconv.ParseUint(fields[3], 8, 32)
		if err != nil || mode > 0o7777 {
			return nil, fmt.Errorf("tree line %d: mode %q is not octal permission bits", n, fields[3])
		}
		if fields[1] == "" || fields[2] == "" {
			return nil, fmt.Errorf("tree line %d: empty owner or group", n)
		}
		rel := path.Clean(identity + rest)
		if _, dup := tree.Rows[rel]; dup {
			return nil, fmt.Errorf("tree line %d: %s listed twice", n, rel)
		}
		tree.Rows[rel] = TreeRow{Owner: fields[1], Group: fields[2], Mode: uint32(mode)}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if _, ok := tree.Rows[identity]; !ok {
		return nil, fmt.Errorf("tree has no row for the store %s", identity)
	}
	return tree, nil
}

// acceptNoStoreCheckValid is the parser's rule for -accept-no-store-check,
// material's rule for -accept-no-sandbox exactly: unset is always valid;
// set, it must equal the OS this observer runs on exactly, and is refused
// outright on linux, where the check runs and there is nothing to accept.
func acceptNoStoreCheckValid(value, goos string) error {
	if value == "" {
		return nil
	}
	if goos == "linux" {
		return fmt.Errorf("accept-no-store-check=%s is refused on linux: own-store-private runs there, so there is nothing to accept", value)
	}
	if value != goos {
		return fmt.Errorf("accept-no-store-check=%s does not name this OS exactly; this observer runs on %q", value, goos)
	}
	return nil
}

// storeEntry is one path of the own store as stat'ed: its path relative to
// /stores/, whether it is a directory, its owner and group ids and its
// twelve permission bits. Required is true for the paths that must exist
// (the root, heartbeat/ and halts/); the rest are compared when present.
type storeEntry struct {
	Rel      string
	Required bool
	Exists   bool
	IsDir    bool
	UID      uint32
	GID      uint32
	Mode     uint32
}

// storeIdentity is who this member runs as: its uid and every group id it
// holds, primary and supplementary.
type storeIdentity struct {
	UID    uint32
	Groups []uint32
}

// idLookup resolves a name from the tree to an id; lookup failures are
// mismatches, never passes.
type idLookup func(name string) (uint32, error)

// ownStorePaths lists the paths of the own store the check compares: the
// root, heartbeat/, halts/, fault and halt when present, and each copy
// directory the store holds (SPEC 2) with its heartbeat/.
func ownStorePaths(cfg *Config) []storeEntry {
	self := cfg.Identity
	out := []storeEntry{
		{Rel: self, Required: true},
		{Rel: path.Join(self, "heartbeat"), Required: true},
		{Rel: path.Join(self, "halts"), Required: true},
		{Rel: path.Join(self, "fault")},
		{Rel: path.Join(self, "halt")},
	}
	for _, cd := range (&reader{cfg: cfg}).copyDirsOf(self) {
		out = append(out, storeEntry{Rel: path.Join(self, cd.Dir)}, storeEntry{Rel: path.Join(self, cd.Dir, "heartbeat")})
	}
	return out
}

// ownStoreMismatches compares the entries against the tree for the member
// self and returns the failing subjects in entry order: the path for an
// entry that is required and absent, could not be stat'ed, has no row in
// the tree, or whose owner, group or mode is not the row's; a file (fault,
// halt) is this member's own and writable by nobody else, so its owner must
// be self and its mode must carry no group or other write bit; and
// <self>/halts:writable when the halts/ directory, whatever the row says,
// is one this member's uid could create in.
// Each owner and group name is resolved once per call (memoLookup), a
// failure as a failure; a call resolves every name afresh.
func ownStoreMismatches(entries []storeEntry, tree *StoreTree, self string, who storeIdentity, uidOf, gidOf idLookup) []string {
	uidOf, gidOf = memoLookup(uidOf), memoLookup(gidOf)
	var out []string
	for _, e := range entries {
		if !e.Exists {
			if e.Required {
				out = append(out, e.Rel)
			}
			continue
		}
		row, ok := tree.Rows[e.Rel]
		if !ok {
			// No row: the member's own files, fault and halt, which the
			// tree does not list because they are created at run time.
			// Anything else without a row, and any directory where a
			// file belongs, is a mismatch.
			if e.IsDir || (e.Rel != path.Join(self, "fault") && e.Rel != path.Join(self, "halt")) || e.UID != who.UID || e.Mode&0o022 != 0 {
				out = append(out, e.Rel)
			}
			continue
		}
		// A row is a directory: a file, or a link, where it belongs is not
		// what the tree says.
		uid, err1 := uidOf(row.Owner)
		gid, err2 := gidOf(row.Group)
		if !e.IsDir || err1 != nil || err2 != nil || uid != e.UID || gid != e.GID || row.Mode != e.Mode {
			out = append(out, e.Rel)
		}
		if e.Rel == path.Join(self, "halts") && canWrite(e, who) {
			out = append(out, e.Rel+":writable")
		}
	}
	return out
}

// memoLookup is lookup answering each name once: the first answer, id or
// error, is every later answer for that name. It is made anew by each
// ownStoreMismatches, so that nothing resolved outlives the cycle.
func memoLookup(lookup idLookup) idLookup {
	type answer struct {
		id  uint32
		err error
	}
	seen := map[string]answer{}
	return func(name string) (uint32, error) {
		if a, ok := seen[name]; ok {
			return a.id, a.err
		}
		id, err := lookup(name)
		seen[name] = answer{id, err}
		return id, err
	}
}

// canWrite is the discretionary rule for creating in a directory: root
// always; the owner by the owner bit alone; a member of the group by the
// group bit; anyone else by the other bit.
func canWrite(e storeEntry, who storeIdentity) bool {
	if who.UID == 0 {
		return true
	}
	if e.UID == who.UID {
		return e.Mode&0o200 != 0
	}
	for _, g := range who.Groups {
		if g == e.GID {
			return e.Mode&0o020 != 0
		}
	}
	return e.Mode&0o002 != 0
}

// ownStorePrivateSubjects is the rule of own-store-private: the subjects it
// fails with, none when it passes, for this observer's acceptance flag and
// the OS it runs on, over the tree and the store on disk.
//
//	goos     flag     tree  -> subjects
//	linux    ""       nil   -> tree
//	linux    ""       read  -> the mismatches (none: pass)
//	linux    set      any   -> the above, then stale-acceptance
//	other    ""       -     -> unsupported
//	other    != goos  -     -> unsupported:acceptance-not-this-os
//	other    goos     -     -> pass
//
// A flag on linux is stale: the check runs there, so there was nothing to
// accept and the acceptance must be withdrawn.
func ownStorePrivateSubjects(cfg *Config, goos string) []string {
	if goos != "linux" {
		switch {
		case cfg.AcceptNoStoreCheck == "":
			return []string{"unsupported"}
		case cfg.AcceptNoStoreCheck != goos:
			return []string{"unsupported:acceptance-not-this-os"}
		}
		return []string{}
	}
	var out []string
	if cfg.OwnTree == nil {
		out = append(out, "tree")
	} else {
		entries, who, err := probeOwnStore(cfg)
		if err != nil {
			out = append(out, cfg.Identity)
		} else {
			out = append(out, ownStoreMismatches(entries, cfg.OwnTree, cfg.Identity, who, lookupUID, lookupGID)...)
		}
	}
	if cfg.AcceptNoStoreCheck != "" {
		out = append(out, "stale-acceptance")
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// refreshOwnStorePrivate probes the own store before a cycle on the real
// disk and records the result in State for the cycle to report. The
// fixture harness does not call this; it supplies the value.
func refreshOwnStorePrivate(cfg *Config, st *State, goos string) {
	st.OwnStorePrivate = ownStorePrivateSubjects(cfg, goos)
}

// lookupUID resolves a user name through the host's account database.
func lookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return parseID(u.Uid)
}

// lookupGID resolves a group name through the host's account database.
func lookupGID(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return parseID(g.Gid)
}

func parseID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("id %q: %v", s, err)
	}
	return uint32(n), nil
}
