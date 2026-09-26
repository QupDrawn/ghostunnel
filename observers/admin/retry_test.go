package main

// retry_test.go: the driver's rename and removal against a file another
// handle holds open without sharing, which on Windows blocks both. The hold
// is holdExclusive; outside Windows it skips the test, and renameFile and
// removeFile are the plain calls (retry_other.go).

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// holdFor is how long a handle is held before it is released under a
// blocked call: long enough to be measurable, short against the budget.
const holdFor = 100 * time.Millisecond

// called is what a call made under a held handle returned, and how long
// the call itself took, measured in the goroutine that made it and not
// around the test's own sleep.
type called struct {
	err     error
	elapsed time.Duration
}

// blocked starts op in a goroutine and returns the channel its result
// arrives on.
func blocked(op func() error) <-chan called {
	r := make(chan called, 1)
	go func() {
		start := time.Now()
		err := op()
		r <- called{err: err, elapsed: time.Since(start)}
	}()
	return r
}

// A rename blocked by a handle that is released after holdFor succeeds
// once the handle is gone, having waited for it.
func TestRenameWaitsForHandle(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "0000000001.hb.tmp")
	writeFile(t, tmp, []byte("x"))
	release := holdExclusive(t, tmp)
	final := filepath.Join(dir, "0000000001.hb")
	r := blocked(func() error { return renameFile(tmp, final) })
	time.Sleep(holdFor)
	release()
	res := <-r
	t.Logf("rename returned after %v (handle held %v)", res.elapsed, holdFor)
	if res.err != nil {
		t.Fatalf("rename: %v", res.err)
	}
	if res.elapsed < holdFor {
		t.Errorf("rename returned before the handle was released: %v", res.elapsed)
	}
	if _, err := os.Stat(final); err != nil {
		t.Errorf("final name absent after the rename: %v", err)
	}
}

// A removal blocked by a handle that is released after holdFor succeeds
// once the handle is gone, having waited for it.
func TestRemoveWaitsForHandle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "0000000001.hb")
	writeFile(t, p, []byte("x"))
	release := holdExclusive(t, p)
	r := blocked(func() error { return removeFile(p) })
	time.Sleep(holdFor)
	release()
	res := <-r
	t.Logf("remove returned after %v (handle held %v)", res.elapsed, holdFor)
	if res.err != nil {
		t.Fatalf("remove: %v", res.err)
	}
	if res.elapsed < holdFor {
		t.Errorf("remove returned before the handle was released: %v", res.elapsed)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Errorf("file still present after the removal: %v", err)
	}
}

// A rename or a removal whose failure is not a sharing violation returns at
// once, with that error.
func TestOtherErrorsAreImmediate(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	err := renameFile(filepath.Join(dir, "absent.tmp"), filepath.Join(dir, "absent"))
	elapsed := time.Since(start)
	t.Logf("rename of an absent source returned after %v", elapsed)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("rename of an absent source: want not-exist, got %v", err)
	}
	if elapsed >= 5*time.Millisecond {
		t.Errorf("rename waited %v on an error that is not a sharing violation", elapsed)
	}
	start = time.Now()
	err = removeFile(filepath.Join(dir, "absent"))
	elapsed = time.Since(start)
	t.Logf("removal of an absent file returned after %v", elapsed)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("removal of an absent file: want not-exist, got %v", err)
	}
	if elapsed >= 5*time.Millisecond {
		t.Errorf("removal waited %v on an error that is not a sharing violation", elapsed)
	}
}
