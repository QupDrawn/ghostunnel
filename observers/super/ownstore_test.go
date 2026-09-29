package main

// ownstore_test.go proves own-store-private (ownstore.go): the tree is read
// as deploy/tree.tsv is written, the comparison over synthetic entries
// finds every kind of mismatch and the one directory this member must not
// be able to write in, the acceptance flag follows material's rule for
// -accept-no-sandbox exactly, and the cycle reports the probe's result as
// its own. The Linux probe (ownstore_linux.go) collects real ownership and
// is not exercised here: a test cannot give a directory another owner.
// Every member carries a byte-identical copy of this file.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The repository's own tree, relative to this package directory.
const deployTree = `../../deploy/tree.tsv`

func TestOwnStoreTreeFromDeploy(t *testing.T) {
	data, err := os.ReadFile(deployTree)
	if err != nil {
		t.Fatalf("deploy/tree.tsv: %v", err)
	}
	for _, id := range []string{"tunnel", "admin", "material", "super"} {
		tree, err := parseStoreTree(data, id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if row := tree.Rows[id]; row.Owner != "root" || row.Group != "gtobs-"+id || row.Mode != 0o1775 {
			t.Errorf("%s: root row %+v", id, row)
		}
		if row := tree.Rows[id+"/halts"]; row.Owner != "root" || row.Group != "gtring-halts-"+id || row.Mode != 0o1775 {
			t.Errorf("%s: halts row %+v", id, row)
		}
		if row := tree.Rows[id+"/heartbeat"]; row.Owner != "gtobs-"+id || row.Mode != 0o755 {
			t.Errorf("%s: heartbeat row %+v", id, row)
		}
		for rel := range tree.Rows {
			if rel != id && !hasPrefix(rel, id+"/") {
				t.Errorf("%s: row %s is another store's", id, rel)
			}
		}
	}
	tunnel, _ := parseStoreTree(data, "tunnel")
	if _, ok := tunnel.Rows["tunnel/copy-super/heartbeat"]; !ok {
		t.Error("tunnel: no row for copy-super/heartbeat")
	}
	super, _ := parseStoreTree(data, "super")
	if _, ok := super.Rows["super/copy-material"]; !ok {
		t.Error("super: no row for copy-material")
	}
}

func TestOwnStoreTreeRefuses(t *testing.T) {
	cases := map[string]string{
		"no root row":  "/x/stores/tunnel/heartbeat\tgtobs-tunnel\tgtobs-tunnel\t0755\n",
		"three fields": "/x/stores/tunnel\troot\t1775\n",
		"bad mode":     "/x/stores/tunnel\troot\tgtobs-tunnel\t0x1775\n",
		"mode too big": "/x/stores/tunnel\troot\tgtobs-tunnel\t17775\n",
		"empty owner":  "/x/stores/tunnel\t\tgtobs-tunnel\t1775\n",
		"twice":        "/x/stores/tunnel\troot\tgtobs-tunnel\t1775\n/x/stores/tunnel\troot\tgtobs-tunnel\t1775\n",
	}
	for name, data := range cases {
		if _, err := parseStoreTree([]byte(data), "tunnel"); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// Comments, blank lines, CRLF and other stores are ignored; a store
	// whose name begins with this identity is not this store.
	data := "# c\r\n\r\n/x/stores/tunnel\troot\tgtobs-tunnel\t1775\r\n/x/stores/tunnel2\troot\tx\t0755\n/x/stores/admin\troot\tgtobs-admin\t1775\n"
	tree, err := parseStoreTree([]byte(data), "tunnel")
	if err != nil || len(tree.Rows) != 1 {
		t.Fatalf("tree %+v, %v", tree, err)
	}
	if _, err := parseStoreTree([]byte(data), ""); err == nil {
		t.Error("an empty identity parsed")
	}
}

// osEntries is a healthy tunnel store as stat'ed under the deploy tree,
// with ids: root 0, gtobs-tunnel 1001, gtobs-material 1002, gtobs-super
// 1003, gtring-halts-tunnel 2001.
func osEntries() []storeEntry {
	return []storeEntry{
		{Rel: "tunnel", Required: true, Exists: true, IsDir: true, UID: 0, GID: 1001, Mode: 0o1775},
		{Rel: "tunnel/heartbeat", Required: true, Exists: true, IsDir: true, UID: 1001, GID: 1001, Mode: 0o755},
		{Rel: "tunnel/halts", Required: true, Exists: true, IsDir: true, UID: 0, GID: 2001, Mode: 0o1775},
		{Rel: "tunnel/fault"},
		{Rel: "tunnel/halt"},
		{Rel: "tunnel/copy", Exists: true, IsDir: true, UID: 1002, GID: 1002, Mode: 0o755},
		{Rel: "tunnel/copy/heartbeat", Exists: true, IsDir: true, UID: 1002, GID: 1002, Mode: 0o755},
		{Rel: "tunnel/copy-super", Exists: true, IsDir: true, UID: 1003, GID: 1003, Mode: 0o755},
		{Rel: "tunnel/copy-super/heartbeat"},
	}
}

var osIDs = map[string]uint32{"root": 0, "gtobs-tunnel": 1001, "gtobs-material": 1002, "gtobs-super": 1003, "gtring-halts-tunnel": 2001}

func osLookup(name string) (uint32, error) {
	if id, ok := osIDs[name]; ok {
		return id, nil
	}
	return 0, errors.New("unknown " + name)
}

func osTree(t *testing.T) *StoreTree {
	t.Helper()
	data, err := os.ReadFile(deployTree)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := parseStoreTree(data, "tunnel")
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

var osSelf = storeIdentity{UID: 1001, Groups: []uint32{1001}}

func osWant(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("mismatches %v, want %v", got, want)
	}
}

func TestOwnStoreHealthyMatches(t *testing.T) {
	osWant(t, ownStoreMismatches(osEntries(), osTree(t), "tunnel", osSelf, osLookup, osLookup))
	// The member's own files, present and its own.
	e := osEntries()
	e[3] = storeEntry{Rel: "tunnel/fault", Exists: true, UID: 1001, GID: 1001, Mode: 0o644}
	e[4] = storeEntry{Rel: "tunnel/halt", Exists: true, UID: 1001, GID: 1001, Mode: 0o600}
	osWant(t, ownStoreMismatches(e, osTree(t), "tunnel", osSelf, osLookup, osLookup))
}

func TestOwnStoreMismatches(t *testing.T) {
	tree := osTree(t)
	mutate := func(i int, f func(e *storeEntry)) []storeEntry {
		e := osEntries()
		f(&e[i])
		return e
	}
	cases := []struct {
		name    string
		entries []storeEntry
		want    []string
	}{
		{"root mode", mutate(0, func(e *storeEntry) { e.Mode = 0o775 }), []string{"tunnel"}},
		{"root group", mutate(0, func(e *storeEntry) { e.GID = 1002 }), []string{"tunnel"}},
		{"heartbeat owner", mutate(1, func(e *storeEntry) { e.UID = 1002 }), []string{"tunnel/heartbeat"}},
		{"heartbeat missing", mutate(1, func(e *storeEntry) { e.Exists = false }), []string{"tunnel/heartbeat"}},
		{"heartbeat a file", mutate(1, func(e *storeEntry) { e.IsDir = false; e.Mode = 0o644 }), []string{"tunnel/heartbeat"}},
		{"halts missing", mutate(2, func(e *storeEntry) { e.Exists = false }), []string{"tunnel/halts"}},
		{"halts world-writable", mutate(2, func(e *storeEntry) { e.Mode = 0o1777 }), []string{"tunnel/halts", "tunnel/halts:writable"}},
		{"halts owned by self", mutate(2, func(e *storeEntry) { e.UID = 1001 }), []string{"tunnel/halts", "tunnel/halts:writable"}},
		{"halts group is self's", mutate(2, func(e *storeEntry) { e.GID = 1001 }), []string{"tunnel/halts", "tunnel/halts:writable"}},
		{"fault another's", mutate(3, func(e *storeEntry) { e.Exists = true; e.UID = 1002; e.Mode = 0o644 }), []string{"tunnel/fault"}},
		{"fault group-writable", mutate(3, func(e *storeEntry) { e.Exists = true; e.UID = 1001; e.Mode = 0o664 }), []string{"tunnel/fault"}},
		{"halt world-writable", mutate(4, func(e *storeEntry) { e.Exists = true; e.UID = 1001; e.Mode = 0o646 }), []string{"tunnel/halt"}},
		{"copy owner", mutate(5, func(e *storeEntry) { e.UID = 1001 }), []string{"tunnel/copy"}},
		{"copy missing", mutate(5, func(e *storeEntry) { e.Exists = false }), nil},
		{"copy-super mode", mutate(7, func(e *storeEntry) { e.Mode = 0o775 }), []string{"tunnel/copy-super"}},
		{"no row", append(osEntries(), storeEntry{Rel: "tunnel/copy-admin", Exists: true, IsDir: true, UID: 0, GID: 0, Mode: 0o755}), []string{"tunnel/copy-admin"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			osWant(t, ownStoreMismatches(c.entries, tree, "tunnel", osSelf, osLookup, osLookup), c.want...)
		})
	}
	// The halts/ group is one this member is in (a deployment that gave it
	// the slot group of its own store): writable, although the row matches.
	self := storeIdentity{UID: 1001, Groups: []uint32{1001, 2001}}
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", self, osLookup, osLookup), "tunnel/halts:writable")
	// A member running as root can write anything: the tree matches the
	// disk, and halts/ is still not private to it.
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", storeIdentity{UID: 0}, osLookup, osLookup), "tunnel/halts:writable")
	// A file where the tree lists none and the member writes none.
	stray := append(osEntries(), storeEntry{Rel: "tunnel/notes", Exists: true, UID: 1001, GID: 1001, Mode: 0o644})
	osWant(t, ownStoreMismatches(stray, tree, "tunnel", osSelf, osLookup, osLookup), "tunnel/notes")
	// A name the host cannot resolve is a mismatch, never a pass.
	unknown := func(name string) (uint32, error) {
		if name == "gtring-halts-tunnel" {
			return 0, errors.New("no such group")
		}
		return osLookup(name)
	}
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", osSelf, osLookup, unknown), "tunnel/halts")
}

// Each name the tree gives is resolved once in a comparison, a failure as a
// failure, and a second comparison resolves every name again: the answers
// are the lookup's, never a remembered one from an earlier cycle.
func TestOwnStoreLookupsOncePerComparison(t *testing.T) {
	tree := osTree(t)
	calls := map[string]int{}
	counting := func(name string) (uint32, error) {
		calls[name]++
		return osLookup(name)
	}
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", osSelf, counting, counting))
	if len(calls) == 0 {
		t.Fatal("no name was resolved")
	}
	for name, n := range calls {
		// One uid lookup and one gid lookup at most: the two are separate
		// namespaces and each is memoized on its own.
		if n > 2 {
			t.Fatalf("%s resolved %d times in one comparison", name, n)
		}
	}
	uids := map[string]int{}
	gids := map[string]int{}
	countUID := func(name string) (uint32, error) { uids[name]++; return osLookup(name) }
	countGID := func(name string) (uint32, error) { gids[name]++; return osLookup(name) }
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", osSelf, countUID, countGID))
	for name, n := range uids {
		if n != 1 {
			t.Fatalf("user %s resolved %d times, want once", name, n)
		}
	}
	for name, n := range gids {
		if n != 1 {
			t.Fatalf("group %s resolved %d times, want once", name, n)
		}
	}
	// A failing lookup is asked once and fails every row that names it.
	failed := 0
	failing := func(name string) (uint32, error) {
		if name == "gtobs-material" {
			failed++
			return 0, errors.New("no such user")
		}
		return osLookup(name)
	}
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", osSelf, failing, osLookup), "tunnel/copy", "tunnel/copy/heartbeat")
	if failed != 1 {
		t.Fatalf("the failing name was asked %d times, want once", failed)
	}
	// The next comparison asks again, and a name that resolves now passes.
	failed = 0
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", osSelf, osLookup, osLookup))
	osWant(t, ownStoreMismatches(osEntries(), tree, "tunnel", osSelf, failing, osLookup), "tunnel/copy", "tunnel/copy/heartbeat")
	if failed != 1 {
		t.Fatalf("a second comparison asked the failing name %d times, want once", failed)
	}
}

func TestOwnStorePaths(t *testing.T) {
	cfg := &Config{Identity: "tunnel", Members: sampleMembers, Coordinator: "super", CopyAuthor: fixtureCopyAuthor}
	var rels []string
	for _, e := range ownStorePaths(cfg) {
		rels = append(rels, e.Rel)
	}
	want := []string{"tunnel", "tunnel/heartbeat", "tunnel/halts", "tunnel/fault", "tunnel/halt", "tunnel/copy", "tunnel/copy/heartbeat", "tunnel/copy-super", "tunnel/copy-super/heartbeat"}
	if fmt.Sprint(rels) != fmt.Sprint(want) {
		t.Fatalf("paths %v, want %v", rels, want)
	}
	cfg.Identity = "super"
	rels = nil
	for _, e := range ownStorePaths(cfg) {
		rels = append(rels, e.Rel)
	}
	want = []string{"super", "super/heartbeat", "super/halts", "super/fault", "super/halt", "super/copy-admin", "super/copy-admin/heartbeat", "super/copy-material", "super/copy-material/heartbeat", "super/copy-tunnel", "super/copy-tunnel/heartbeat"}
	if fmt.Sprint(rels) != fmt.Sprint(want) {
		t.Fatalf("super paths %v, want %v", rels, want)
	}
}

// TestOwnStorePrivateRule is the rule over the OS and the acceptance, the
// OS injected so that every row is made on any host. The rows that probe
// a real store are the Linux probe's and are not here.
func TestOwnStorePrivateRule(t *testing.T) {
	cases := []struct {
		goos, flag string
		tree       *StoreTree
		want       []string
	}{
		{"windows", "", nil, []string{"unsupported"}},
		{"windows", "windows", nil, []string{}},
		{"windows", "darwin", nil, []string{"unsupported:acceptance-not-this-os"}},
		{"darwin", "", nil, []string{"unsupported"}},
		{"linux", "", nil, []string{"tree"}},
		{"linux", "linux", nil, []string{"tree", "stale-acceptance"}},
	}
	for _, c := range cases {
		t.Run(c.goos+"/"+c.flag, func(t *testing.T) {
			cfg := &Config{Identity: "tunnel", AcceptNoStoreCheck: c.flag, OwnTree: c.tree}
			got := ownStorePrivateSubjects(cfg, c.goos)
			if got == nil || fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("subjects %#v, want %v", got, c.want)
			}
			st := &State{}
			refreshOwnStorePrivate(cfg, st, c.goos)
			if fmt.Sprint(st.OwnStorePrivate) != fmt.Sprint(c.want) {
				t.Fatalf("state %v, want %v", st.OwnStorePrivate, c.want)
			}
		})
	}
}

func TestAcceptNoStoreCheckFlag(t *testing.T) {
	if err := acceptNoStoreCheckValid("", "linux"); err != nil {
		t.Errorf("unset on linux: %v", err)
	}
	if err := acceptNoStoreCheckValid("", "windows"); err != nil {
		t.Errorf("unset on windows: %v", err)
	}
	if err := acceptNoStoreCheckValid("windows", "windows"); err != nil {
		t.Errorf("windows on windows: %v", err)
	}
	if err := acceptNoStoreCheckValid("linux", "linux"); err == nil {
		t.Error("linux on linux accepted")
	}
	if err := acceptNoStoreCheckValid("darwin", "windows"); err == nil {
		t.Error("darwin on windows accepted")
	}
	if err := acceptNoStoreCheckValid("Windows", "windows"); err == nil {
		t.Error("a value not exactly the OS accepted")
	}
}

// TestOwnStorePrivateInTheCycle is the cycle's side: the probe's result is
// reported as own-store-private, a local finding, and nothing probed is
// nothing passed.
func TestOwnStorePrivateInTheCycle(t *testing.T) {
	cfg, st, _ := fixtureCopy(t, "healthy-ring")
	got, out := cycleFindings(t, cfg, st)
	if len(got) != 0 {
		t.Fatalf("healthy ring with the probe satisfied: %v", got)
	}
	if !contains(out.Publish.Checks, "own-store-private") {
		t.Fatalf("checks %v do not list own-store-private", out.Publish.Checks)
	}
	st.OwnStorePrivate = nil
	got, _ = cycleFindings(t, cfg, st)
	if fmt.Sprint(got) != fmt.Sprint([]string{"own-store-private(unprobed)"}) {
		t.Fatalf("unprobed: %v", got)
	}
	st.OwnStorePrivate = []string{"tunnel/halts:writable", "tunnel/copy"}
	got, out = cycleFindings(t, cfg, st)
	if fmt.Sprint(got) != fmt.Sprint([]string{"own-store-private(tunnel/halts:writable)", "own-store-private(tunnel/copy)"}) {
		t.Fatalf("mismatches: %v", got)
	}
	if len(out.Fault.Local) != 2 || !out.Fault.Publish {
		t.Fatalf("own-store-private is local and belongs in the fault: %+v", out.Fault)
	}
	if !out.Halt.Writes || out.Halt.Reason != "own-store-private" || out.Halt.Subject != "tunnel/halts:writable" {
		t.Fatalf("halt %+v", out.Halt)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// TestOwnStorePathsOnDisk is the Linux probe's shape on any host: the
// entries it returns are the paths, marked present where the store has
// them. On a build with no probe it returns an error, and the rule never
// reaches it.
func TestOwnStoreProbeShape(t *testing.T) {
	tmp := t.TempDir()
	cfg := &Config{Identity: "tunnel", Members: sampleMembers, Coordinator: "super", CopyAuthor: fixtureCopyAuthor, StoresRoot: tmp}
	for _, d := range []string{"tunnel/heartbeat", "tunnel/halts", "tunnel/copy"} {
		if err := os.MkdirAll(filepath.Join(tmp, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	entries, _, err := probeOwnStore(cfg)
	if err != nil {
		t.Skipf("no probe on this build: %v", err)
	}
	present := map[string]bool{}
	for _, e := range entries {
		present[e.Rel] = e.Exists
	}
	for _, rel := range []string{"tunnel", "tunnel/heartbeat", "tunnel/halts", "tunnel/copy"} {
		if !present[rel] {
			t.Errorf("%s not seen present", rel)
		}
	}
	for _, rel := range []string{"tunnel/fault", "tunnel/copy-super"} {
		if present[rel] {
			t.Errorf("%s seen present", rel)
		}
	}
}
