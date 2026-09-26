//go:build windows

package main

import (
	"sync"
	"syscall"
	"testing"
)

// holdExclusive opens p from this test with no sharing at all: while the
// handle is held every other open of the file fails with a sharing
// violation, and a rename or a removal of it fails the same way, while the
// file stays listed and can be stat'ed. That is the on-disk state of an
// entry present but unreadable, and of a writer-side rename blocked the
// same way. The returned release closes the handle once; the test's
// cleanup closes it if the test did not.
func holdExclusive(t *testing.T, p string) (release func()) {
	t.Helper()
	pp, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(pp, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() { once.Do(func() { syscall.CloseHandle(h) }) }
	t.Cleanup(release)
	return release
}

// An entry held open elsewhere without sharing is present, listed and
// stat'able, and cannot be read: S5, and not I7 for its copy.
func TestEntryHeldOpenIsS5(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	holdExclusive(t, hbPath(tmp, "material", 43, "heartbeat"))
	_, out := cycleFindings(t, cfg, st)
	if !hasFinding(out, "S5", "material/heartbeat/0000000043.hb") {
		t.Errorf("S5 missing from %v", out.Failing)
	}
	if hasFinding(out, "I7", "material") {
		t.Errorf("I7 fired for an original listed but not read: %v", out.Failing)
	}
	if hasFinding(out, "copy-current", "material") {
		t.Errorf("copy-current fired: %v", out.Failing)
	}
}
