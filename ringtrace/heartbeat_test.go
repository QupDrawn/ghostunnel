package ringtrace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setReadBoundedHook installs hook between readBounded's lstat and its
// open for the rest of the test.
func setReadBoundedHook(t *testing.T, hook func(path string)) {
	t.Helper()
	readBoundedHook = hook
	t.Cleanup(func() { readBoundedHook = nil })
}

// readBoundedWithin runs readBounded and fails the test when it has not
// returned within the limit: a read that waits is the failure. release
// is called to let a waiting read go before the test fails.
func readBoundedWithin(t *testing.T, path string, max int64, release func()) ([]byte, error) {
	t.Helper()
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := readBounded(path, max)
		done <- result{data, err}
	}()
	select {
	case r := <-done:
		return r.data, r.err
	case <-time.After(5 * time.Second):
		release()
		<-done
		t.Fatalf("readBounded(%s) still waiting after 5s", path)
		return nil, nil
	}
}

func TestReadBoundedReadsARegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	writeRaw(t, path, "hello")
	data, err := readBounded(path, 5)
	if err != nil || string(data) != "hello" {
		t.Fatalf("got %q, %v", data, err)
	}
	if _, err := readBounded(path, 4); err == nil {
		t.Fatal("a file above the bound was read")
	}
}

// A named pipe at the name is refused by the lstat, before any open.
func TestReadBoundedRefusesANamedPipe(t *testing.T) {
	if noFIFO != "" {
		t.Skip(noFIFO)
	}
	path := filepath.Join(t.TempDir(), "0000000042.hb")
	if err := mkfifo(path); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedWithin(t, path, 1024, func() { releaseFIFO(path) }); err == nil {
		t.Fatal("a named pipe was read")
	}
}

// A named pipe put in the file's place after the lstat is opened without
// waiting and refused on the open file: the read returns at once.
func TestReadBoundedRefusesANamedPipeSwappedIn(t *testing.T) {
	if noFIFO != "" {
		t.Skip(noFIFO)
	}
	path := filepath.Join(t.TempDir(), "0000000042.hb")
	writeRaw(t, path, "x")
	setReadBoundedHook(t, func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := mkfifo(p); err != nil {
			t.Error(err)
		}
	})
	_, err := readBoundedWithin(t, path, 1024, func() { releaseFIFO(path) })
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a named pipe swapped in after the lstat: %v", err)
	}
}

// The gate's scan returns, refusing, when a named pipe replaces the
// coordinator's newest heartbeat between its lstat and its open.
func TestGateRefusesANamedPipeSwappedIntoTheHeartbeat(t *testing.T) {
	if noFIFO != "" {
		t.Skip(noFIFO)
	}
	root := healthyTree(t)
	hb := filepath.Join(root, "super", "heartbeat", "0000000042.hb")
	setReadBoundedHook(t, func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := mkfifo(p); err != nil {
			t.Error(err)
		}
	})
	done := make(chan Decision, 1)
	go func() { done <- testGate(root).Check() }()
	select {
	case d := <-done:
		if d.Serve || !strings.Contains(d.Reason, "super/heartbeat/0000000042.hb") {
			t.Fatalf("a named pipe in the heartbeat's place: %+v", d)
		}
	case <-time.After(5 * time.Second):
		releaseFIFO(hb)
		<-done
		t.Fatal("the gate's scan still waiting after 5s on a named pipe")
	}
}

// Another regular file renamed over the name after the lstat is not the
// file the lstat found: refused, on every platform.
func TestReadBoundedRefusesAFileSwappedIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0000000042.hb")
	writeRaw(t, path, "first")
	other := filepath.Join(dir, "other")
	writeRaw(t, other, "other")
	setReadBoundedHook(t, func(p string) {
		if err := os.Rename(other, p); err != nil {
			t.Error(err)
		}
	})
	data, err := readBoundedWithin(t, path, 1024, func() {})
	if err == nil || !strings.Contains(err.Error(), "changed between the lstat and the open") {
		t.Fatalf("a file swapped in after the lstat: %q, %v", data, err)
	}
}

// A symbolic link put in the file's place after the lstat is not
// followed: refused.
func TestReadBoundedRefusesALinkSwappedIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0000000042.hb")
	writeRaw(t, path, "first")
	target := filepath.Join(dir, "target")
	writeRaw(t, target, "other")
	probe := filepath.Join(dir, "probe")
	if err := os.Symlink(target, probe); err != nil {
		t.Skipf("symbolic links cannot be made here: %v", err)
	}
	setReadBoundedHook(t, func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Error(err)
		}
	})
	if data, err := readBoundedWithin(t, path, 1024, func() {}); err == nil {
		t.Fatalf("a link swapped in after the lstat was followed: %q", data)
	}
}
