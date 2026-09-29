//go:build windows

package ringtrace

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

// testFilter is the filter over a healthy tree with the default members.
func testFilter(t *testing.T) (*notifyFilter, string) {
	t.Helper()
	root := healthyTree(t)
	f := newNotifyFilter(root, testGate(root))
	if !f.on {
		t.Fatal("the filter is off over a healthy tree")
	}
	return f, root
}

func TestNotifyFilterCountsWhatTheGateReads(t *testing.T) {
	f, _ := testFilter(t)
	counted := []string{
		"", `admin`, `admin\halt`, `admin\fault`, `admin\halt.tmp`, `admin\halts`, `admin\halts\super`,
		`super\halts\tunnel.tmp`, `super\heartbeat`, `super\heartbeat\0000000043.hb`, `SUPER\HeartBeat\0000000043.hb`,
		`super\HEARTB~1\0000000043.hb`, `tunnel\HEARTB~1\0000000001.hb`, `tunnel\COPY~1\heartbeat\x`, `GT~1\x`,
		`gt`, `GT`, `other\x`, `super`, `tunnel\copy`, `tunnel\copy-super`, `tunnel\heartbeat`, `tunnel\h\x`,
		"tunnel\\ｃopy\\x", "gt́\\x", `tunnel\co:py\x`, `.\gt\x`, `tunnel\.\heartbeat\x`,
		`admin\halts\copy\x`, `super\copy`, `material\fault`,
	}
	for _, rel := range counted {
		if !f.counts(rel) {
			t.Errorf("%q is not counted", rel)
		}
	}
	ignored := []string{
		`gt\lock`, `gt\0000000001\0000000001.trace`, `GT\chains\x.der`, `gt\material\x`,
		`tunnel\copy\heartbeat\0000000001.hb`, `tunnel\COPY-super\heartbeat\x`, `super\copy\x`, `admin\copy2\x\y`,
		`admin\heartbeat\0000000001.hb`, `MATERIAL\Heartbeat\0000000001.hb.tmp`, `tunnel\heartbeat\x\y`,
	}
	for _, rel := range ignored {
		if f.counts(rel) {
			t.Errorf("%q is counted", rel)
		}
	}
	if !f.on {
		t.Fatal("the filter turned off over a healthy tree")
	}
}

func TestNotifyFilterIsOffForAMemberNamedGT(t *testing.T) {
	root := healthyTree(t)
	if err := os.MkdirAll(filepath.Join(root, "gt", "halts"), 0o755); err != nil {
		t.Fatal(err)
	}
	g := testGate(root)
	g.Members = []string{"admin", "gt", "material", "super", "tunnel"}
	f := newNotifyFilter(root, g)
	if !f.counts(`gt\halts\x`) || !f.counts(`GT\halt`) {
		t.Fatal("a member named gt is not counted")
	}
	g.Members = []string{"admin", `a\b`, "super"}
	if f := newNotifyFilter(root, g); f.on || !f.counts(`gt\x`) {
		t.Fatal("the filter is on over a member that is not one plain name")
	}
}

// junction makes link a junction to target, which needs no privilege.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("no junction can be made here: %v: %s", err, out)
	}
}

// A directory the gate reads through that is a reparse point may lead into
// a subtree that is not counted: the filter is off from the start, or from
// the notification that names it.
func TestNotifyFilterIsOffOverALinkedDirectory(t *testing.T) {
	for _, dir := range []string{`super\heartbeat`, `admin\halts`, `material`} {
		root := healthyTree(t)
		target := filepath.Join(root, "tunnel", "copy", "heartbeat")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		f := newNotifyFilter(root, testGate(root))
		if !f.on {
			t.Fatal("the filter is off over a healthy tree")
		}
		if err := os.RemoveAll(filepath.Join(root, dir)); err != nil {
			t.Fatal(err)
		}
		junction(t, filepath.Join(root, dir), target)
		// The link's own notification comes before any from inside it.
		f.counts(dir)
		if f.on || !f.counts(`tunnel\copy\heartbeat\x`) {
			t.Fatalf("%s: the filter is still on after the notification that names the link", dir)
		}
		if f := newNotifyFilter(root, testGate(root)); f.on {
			t.Fatalf("%s: the filter is on over a linked directory", dir)
		}
		// A name that cannot be told apart from a read directory's checks
		// them all.
		if err := os.RemoveAll(filepath.Join(root, dir)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		f = newNotifyFilter(root, testGate(root))
		if err := os.RemoveAll(filepath.Join(root, dir)); err != nil {
			t.Fatal(err)
		}
		junction(t, filepath.Join(root, dir), target)
		f.counts(`super\HEARTB~1`)
		if f.on {
			t.Fatalf("%s: the filter is still on after a short name", dir)
		}
	}
}

// notifyBuffer lays out FILE_NOTIFY_INFORMATION entries for names.
func notifyBuffer(names ...string) []byte {
	var b []byte
	for i, name := range names {
		u := utf16.Encode([]rune(name))
		size := 12 + 2*len(u)
		size = (size + 3) &^ 3
		e := make([]byte, size)
		if i < len(names)-1 {
			binary.LittleEndian.PutUint32(e[0:], uint32(size))
		}
		binary.LittleEndian.PutUint32(e[4:], 3)
		binary.LittleEndian.PutUint32(e[8:], uint32(2*len(u)))
		for j, c := range u {
			binary.LittleEndian.PutUint16(e[12+2*j:], c)
		}
		b = append(b, e...)
	}
	return b
}

func TestCountNotifications(t *testing.T) {
	f, _ := testFilter(t)
	if n, ig := countNotifications(notifyBuffer(`gt\0000000001\0000000001.trace`, `tunnel\copy\heartbeat\x`), f); n != 0 || ig != 2 {
		t.Fatalf("got %d counted, %d ignored; want 0, 2", n, ig)
	}
	if n, ig := countNotifications(notifyBuffer(`gt\lock`, `super\halt`, `gt\x`), f); n != 1 || ig != 2 {
		t.Fatalf("got %d counted, %d ignored; want 1, 2", n, ig)
	}
	// A name that runs past the buffer is counted.
	b := notifyBuffer(`gt\x`)
	binary.LittleEndian.PutUint32(b[8:], 1000)
	if n, _ := countNotifications(b, f); n != 1 {
		t.Fatalf("a truncated entry: %d counted, want 1", n)
	}
	if n, _ := countNotifications([]byte{1, 2, 3}, f); n != 1 {
		t.Fatalf("a buffer with no whole entry: %d counted, want 1", n)
	}
}

// The real watcher: writes under gt\ and under a store's copy of another's
// heartbeat reach it and do not make the next check scan; a halt, a fault,
// a halts\ slot and a coordinator heartbeat each do.
func TestGateStateWatcherIgnoresWhatTheGateNeverReads(t *testing.T) {
	s, root, clock := testState(t)
	for _, d := range []string{filepath.Join("gt", "0000000001"), filepath.Join("tunnel", "copy", "heartbeat")} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Watch(); err != nil {
		t.Fatal(err)
	}
	w := s.watcher.(*rdcWatcher)
	if !w.filter.on {
		t.Fatal("the filter is off over a healthy tree")
	}
	if d := s.Check(); !d.Serve {
		t.Fatal(d.Reason)
	}
	// Let what the tree's creation reports arrive and absorb it.
	time.Sleep(100 * time.Millisecond)
	clock.Advance(time.Millisecond)
	s.Check()

	for i, rel := range []string{
		filepath.Join("gt", "0000000001", "0000000001.trace"),
		filepath.Join("gt", "0000000001", "0000000001.trace"),
		filepath.Join("tunnel", "copy", "heartbeat", "0000000007.hb"),
	} {
		scans, events, ignored := s.Scans(), s.Events(), w.ignored.Load()
		writeRaw(t, filepath.Join(root, rel), "line\n")
		deadline := time.Now().Add(2 * time.Second)
		for w.ignored.Load() == ignored && s.Events() == events {
			if time.Now().After(deadline) {
				t.Fatalf("write %d under %s: no notification within 2 s", i, rel)
			}
			s.Check()
			time.Sleep(time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		clock.Advance(time.Millisecond)
		if d := s.Check(); !d.Serve {
			t.Fatal(d.Reason)
		}
		if s.Events() != events || s.Scans() != scans {
			t.Fatalf("write %d under %s: %d events and %d scans, want %d and %d", i, rel, s.Events(), s.Scans(), events, scans)
		}
	}

	for _, c := range []struct {
		what, path string
		serve      bool
	}{
		{"a halt", filepath.Join(root, "admin", "halt"), false},
		{"a fault", filepath.Join(root, "tunnel", "fault"), false},
		{"a halts slot", filepath.Join(root, "material", "halts", "super"), false},
	} {
		scans, events := s.Scans(), s.Events()
		writeRaw(t, c.path, "x")
		waitEvents(t, s, events)
		clock.Advance(time.Millisecond)
		if d := s.Check(); d.Serve {
			t.Fatalf("%s: served after the watcher reported it", c.what)
		}
		if got := s.Scans(); got != scans+1 {
			t.Fatalf("%s: %d scans, want %d", c.what, got, scans+1)
		}
		events = s.Events()
		if err := os.Remove(c.path); err != nil {
			t.Fatal(err)
		}
		waitEvents(t, s, events)
		clock.Advance(time.Millisecond)
		if d := s.Check(); !d.Serve {
			t.Fatalf("%s removed: %s", c.what, d.Reason)
		}
	}

	scans, events := s.Scans(), s.Events()
	writeHB(t, root, "super", 43, gateNow.Add(-time.Second).Format("2006-01-02T15:04:05Z"), true)
	waitEvents(t, s, events)
	clock.Advance(time.Millisecond)
	if d := s.Check(); d.Serve {
		t.Fatal("served after the watcher reported a stop heartbeat")
	}
	if got := s.Scans(); got != scans+1 {
		t.Fatalf("a coordinator heartbeat: %d scans, want %d", got, scans+1)
	}
}

// An overflow loses the notifications that would have named a directory
// the gate reads through: the filter checks them all again.
func TestNotifyFilterIsCheckedAgainOnOverflow(t *testing.T) {
	rdcBufferBytes = 16
	t.Cleanup(func() { rdcBufferBytes = 64 * 1024 })
	s, root, _ := testState(t)
	target := filepath.Join(root, "tunnel", "copy", "heartbeat")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Watch(); err != nil {
		t.Fatal(err)
	}
	w := s.watcher.(*rdcWatcher)
	if !w.filter.on {
		t.Fatal("the filter is off over a healthy tree")
	}
	overflows := s.Overflows()
	if err := os.RemoveAll(filepath.Join(root, "super", "heartbeat")); err != nil {
		t.Fatal(err)
	}
	junction(t, filepath.Join(root, "super", "heartbeat"), target)
	deadline := time.Now().Add(2 * time.Second)
	for s.Overflows() == overflows {
		if time.Now().After(deadline) {
			t.Fatal("no overflow within 2 s")
		}
		s.Check()
		time.Sleep(time.Millisecond)
	}
	s.Check()
	w.mu.Lock()
	on := w.filter.on
	w.mu.Unlock()
	if on {
		t.Fatal("the filter is still on after an overflow over a linked directory")
	}
}
