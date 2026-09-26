//go:build windows

package main

// readretry_windows_test.go: the reader's reads against a file another
// handle holds open without sharing, which on Windows makes every open of
// it fail with a sharing violation while the file stays listed and
// stat'able, as a scanner holding a freshly written heartbeat for an
// instant does. A hold released within the budget must leave no finding,
// as it leaves none on Linux; a hold outlasting the budget is S5; and a
// read that fails for any other reason returns at once.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readBudget is the least time a read spends on a handle never released:
// every interval between the attempts.
var readBudget = time.Duration(retryAttempts-1) * retryInterval

// releaseAfter releases a held handle from another goroutine after d, so
// the call under test runs in the test's own goroutine and is timed there.
func releaseAfter(release func(), d time.Duration) {
	go func() {
		time.Sleep(d)
		release()
	}()
}

// heartbeatBytes returns the bytes of the fixture's material/43 entry.
func heartbeatBytes(t *testing.T, tmp string) []byte {
	t.Helper()
	b, err := os.ReadFile(hbPath(tmp, "material", 43, "heartbeat"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- readBounded ----------------------------------------------------------

func TestReadBoundedWaitsForHandle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "0000000001.hb")
	writeFile(t, p, []byte("x"))
	release := holdExclusive(t, p)
	releaseAfter(release, holdFor)
	start := time.Now()
	data, oversized, err := readBounded(p, 8192)
	elapsed := time.Since(start)
	t.Logf("readBounded returned after %v (handle held %v)", elapsed, holdFor)
	if err != nil || oversized {
		t.Fatalf("readBounded: oversized=%v err=%v", oversized, err)
	}
	if string(data) != "x" {
		t.Errorf("bytes: got %q", data)
	}
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestReadBoundedGivesUpAfterBudget(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "0000000001.hb")
	writeFile(t, p, []byte("x"))
	holdExclusive(t, p) // released only by the test's cleanup
	start := time.Now()
	_, oversized, err := readBounded(p, 8192)
	elapsed := time.Since(start)
	t.Logf("readBounded gave up after %v (budget %v)", elapsed, readBudget)
	if err == nil || oversized {
		t.Fatalf("readBounded succeeded against a handle that was never released (oversized=%v)", oversized)
	}
	if !sharingError(err) {
		t.Errorf("error is not a sharing violation: %v", err)
	}
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
	if elapsed > 4*readBudget {
		t.Errorf("gave up after %v, far beyond the budget of %v", elapsed, readBudget)
	}
}

// --- readPrefix -----------------------------------------------------------

func TestReadPrefixWaitsForHandle(t *testing.T) {
	_, _, tmp := fixtureCopy(t, "healthy-ring")
	p := filepath.Join(t.TempDir(), "stray")
	writeFile(t, p, heartbeatBytes(t, tmp))
	release := holdExclusive(t, p)
	releaseAfter(release, holdFor)
	start := time.Now()
	prefix := readPrefix(p)
	elapsed := time.Since(start)
	t.Logf("readPrefix returned after %v (handle held %v)", elapsed, holdFor)
	if classify(prefix) != KindHeartbeat {
		t.Errorf("prefix %q does not classify as a heartbeat", prefix)
	}
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestReadPrefixGivesUpAfterBudget(t *testing.T) {
	_, _, tmp := fixtureCopy(t, "healthy-ring")
	p := filepath.Join(t.TempDir(), "stray")
	writeFile(t, p, heartbeatBytes(t, tmp))
	holdExclusive(t, p)
	start := time.Now()
	prefix := readPrefix(p)
	elapsed := time.Since(start)
	t.Logf("readPrefix gave up after %v (budget %v)", elapsed, readBudget)
	if prefix != nil {
		t.Errorf("readPrefix read %q against a handle that was never released", prefix)
	}
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
	if elapsed > 4*readBudget {
		t.Errorf("gave up after %v, far beyond the budget of %v", elapsed, readBudget)
	}
}

// A stray file in a heartbeat folder, held for an instant, is classified
// by its prefix once the handle is gone (I6 for heartbeat bytes); held past
// the budget it classifies as nothing (S1).
func TestStrayHeldBrieflyIsClassified(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	dir := filepath.Dir(hbPath(tmp, "material", 43, "heartbeat"))
	p := filepath.Join(dir, "stray")
	writeFile(t, p, heartbeatBytes(t, tmp))
	release := holdExclusive(t, p)
	releaseAfter(release, holdFor)
	r := newReader(cfg, st)
	r.runC(dir, "material/heartbeat", "material")
	if !r.hasFinding("I6", "material/heartbeat/stray") {
		t.Errorf("I6 missing for a stray heartbeat held only for %v: %v", holdFor, r.findings)
	}
	if r.hasFinding("S1", "material/heartbeat/stray") {
		t.Errorf("S1 fired for a stray heartbeat held only for %v: %v", holdFor, r.findings)
	}
}

func TestStrayHeldPastBudgetIsS1(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	dir := filepath.Dir(hbPath(tmp, "material", 43, "heartbeat"))
	p := filepath.Join(dir, "stray")
	writeFile(t, p, heartbeatBytes(t, tmp))
	holdExclusive(t, p)
	r := newReader(cfg, st)
	r.runC(dir, "material/heartbeat", "material")
	if !r.hasFinding("S1", "material/heartbeat/stray") {
		t.Errorf("S1 missing for a stray file that could never be read: %v", r.findings)
	}
	if r.hasFinding("I6", "material/heartbeat/stray") {
		t.Errorf("I6 fired for a stray file that could never be read: %v", r.findings)
	}
}

// --- procedure C ----------------------------------------------------------

// An entry held open for an instant is read and parsed once the handle is
// gone: no S5, and procedure C took about as long as the hold.
func TestEntryHeldBrieflyIsReadAndParsed(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	p := hbPath(tmp, "material", 43, "heartbeat")
	release := holdExclusive(t, p)
	releaseAfter(release, holdFor)
	r := newReader(cfg, st)
	start := time.Now()
	res := r.runC(filepath.Dir(p), "material/heartbeat", "material")
	elapsed := time.Since(start)
	t.Logf("procedure C returned after %v (handle held %v)", elapsed, holdFor)
	if r.hasFinding("S5", "material/heartbeat/0000000043.hb") {
		t.Errorf("S5 fired for an entry held only for %v: %v", holdFor, r.findings)
	}
	e := res.bySequence()[43]
	if e == nil {
		t.Fatal("entry 43 not listed")
	}
	if !e.Read || !e.Parsed {
		t.Errorf("entry 43: Read=%v Parsed=%v", e.Read, e.Parsed)
	}
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

// An entry held open past the budget is still present and still
// unreadable: S5, after the budget was spent.
func TestEntryHeldPastBudgetIsS5(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	p := hbPath(tmp, "material", 43, "heartbeat")
	holdExclusive(t, p)
	r := newReader(cfg, st)
	start := time.Now()
	res := r.runC(filepath.Dir(p), "material/heartbeat", "material")
	elapsed := time.Since(start)
	t.Logf("procedure C gave up after %v (budget %v)", elapsed, readBudget)
	if !r.hasFinding("S5", "material/heartbeat/0000000043.hb") {
		t.Errorf("S5 missing for an entry that could never be read: %v", r.findings)
	}
	e := res.bySequence()[43]
	if e == nil {
		t.Fatal("entry 43 not listed")
	}
	if e.Read || e.Parsed {
		t.Errorf("entry 43: Read=%v Parsed=%v against a handle that was never released", e.Read, e.Parsed)
	}
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
	if elapsed > 4*readBudget {
		t.Errorf("gave up after %v, far beyond the budget of %v", elapsed, readBudget)
	}
}

// The same through a whole cycle: an entry held for an instant leaves no
// finding at all, as on Linux.
func TestCycleEntryHeldBrieflyIsClean(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	release := holdExclusive(t, hbPath(tmp, "material", 43, "heartbeat"))
	releaseAfter(release, holdFor)
	start := time.Now()
	keys, out := cycleFindings(t, cfg, st)
	elapsed := time.Since(start)
	t.Logf("cycle returned after %v (handle held %v)", elapsed, holdFor)
	if len(keys) != 0 {
		t.Errorf("findings on a healthy ring with one entry held for %v: %v", holdFor, out.Failing)
	}
	if elapsed < holdFor {
		t.Errorf("cycle returned before the handle was released: %v", elapsed)
	}
}

// --- checkI5 --------------------------------------------------------------

func TestOwnEntryHeldBrieflyIsNotI5(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	release := holdExclusive(t, hbPath(tmp, "tunnel", 44, "heartbeat"))
	releaseAfter(release, holdFor)
	r := newReader(cfg, st)
	start := time.Now()
	r.checkI5()
	elapsed := time.Since(start)
	t.Logf("checkI5 returned after %v (handle held %v)", elapsed, holdFor)
	if len(r.findings) != 0 {
		t.Errorf("I5 on an own entry held only for %v: %v", holdFor, r.findings)
	}
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestOwnEntryHeldPastBudgetIsI5(t *testing.T) {
	cfg, st, tmp := fixtureCopy(t, "healthy-ring")
	holdExclusive(t, hbPath(tmp, "tunnel", 44, "heartbeat"))
	r := newReader(cfg, st)
	start := time.Now()
	r.checkI5()
	elapsed := time.Since(start)
	t.Logf("checkI5 gave up after %v (budget %v)", elapsed, readBudget)
	if !r.hasFinding("I5", "tunnel/heartbeat/0000000044.hb") {
		t.Errorf("I5 missing for an own entry that could never be read: %v", r.findings)
	}
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
}

// --- traces.go ------------------------------------------------------------

const sampleTrace = `{"kind":"trace","version":1,"schedule":"nightly","run":7,"started":"2026-09-20T10:00:00Z"}` + "\n"

func TestReadTraceWaitsForHandle(t *testing.T) {
	p := filepath.Join(t.TempDir(), "0000000007.trace")
	writeFile(t, p, []byte(sampleTrace))
	release := holdExclusive(t, p)
	releaseAfter(release, holdFor)
	start := time.Now()
	tr := readTrace(p, "nightly", 7)
	elapsed := time.Since(start)
	t.Logf("readTrace returned after %v (handle held %v)", elapsed, holdFor)
	if tr.Malformed {
		t.Errorf("trace malformed although the handle was released after %v", holdFor)
	}
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestReadTraceGivesUpAfterBudget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "0000000007.trace")
	writeFile(t, p, []byte(sampleTrace))
	holdExclusive(t, p)
	start := time.Now()
	tr := readTrace(p, "nightly", 7)
	elapsed := time.Since(start)
	t.Logf("readTrace gave up after %v (budget %v)", elapsed, readBudget)
	if !tr.Malformed {
		t.Error("trace read against a handle that was never released")
	}
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
}

func TestReadObservingSinceWaitsForHandle(t *testing.T) {
	own := t.TempDir()
	p := filepath.Join(own, observingSinceName)
	writeFile(t, p, []byte("2026-09-20T10:00:00Z\n"))
	release := holdExclusive(t, p)
	releaseAfter(release, holdFor)
	start := time.Now()
	since := readObservingSince(own)
	elapsed := time.Since(start)
	t.Logf("readObservingSince returned after %v (handle held %v)", elapsed, holdFor)
	if since == nil {
		t.Errorf("since nil although the handle was released after %v", holdFor)
	}
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestReadObservingSinceGivesUpAfterBudget(t *testing.T) {
	own := t.TempDir()
	p := filepath.Join(own, observingSinceName)
	writeFile(t, p, []byte("2026-09-20T10:00:00Z\n"))
	holdExclusive(t, p)
	start := time.Now()
	since := readObservingSince(own)
	elapsed := time.Since(start)
	t.Logf("readObservingSince gave up after %v (budget %v)", elapsed, readBudget)
	if since != nil {
		t.Error("since read against a handle that was never released")
	}
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
}

// --- everything else is immediate -----------------------------------------

// A read that fails with not-exist, or with anything but a sharing
// violation, returns at once with that error.
func TestAbsentReadsAreImmediate(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "0000000001.hb")
	start := time.Now()
	_, _, err := readBounded(absent, 8192)
	elapsed := time.Since(start)
	t.Logf("readBounded of an absent file returned after %v", elapsed)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("readBounded of an absent file: want not-exist, got %v", err)
	}
	if elapsed >= 5*time.Millisecond {
		t.Errorf("readBounded waited %v on not-exist", elapsed)
	}
	start = time.Now()
	prefix := readPrefix(absent)
	elapsed = time.Since(start)
	t.Logf("readPrefix of an absent file returned after %v", elapsed)
	if prefix != nil {
		t.Errorf("readPrefix of an absent file: got %q", prefix)
	}
	if elapsed >= 5*time.Millisecond {
		t.Errorf("readPrefix waited %v on not-exist", elapsed)
	}
	start = time.Now()
	tr := readTrace(absent, "nightly", 1)
	elapsed = time.Since(start)
	t.Logf("readTrace of an absent file returned after %v", elapsed)
	if !tr.Malformed {
		t.Error("readTrace of an absent file: not malformed")
	}
	if elapsed >= 5*time.Millisecond {
		t.Errorf("readTrace waited %v on not-exist", elapsed)
	}
	start = time.Now()
	since := readObservingSince(dir)
	elapsed = time.Since(start)
	t.Logf("readObservingSince without a since file returned after %v", elapsed)
	if since != nil {
		t.Error("readObservingSince without a since file: not nil")
	}
	if elapsed >= 5*time.Millisecond {
		t.Errorf("readObservingSince waited %v on not-exist", elapsed)
	}
	// A directory where a file is expected is not a sharing violation.
	start = time.Now()
	_, _, err = readBounded(dir, 8192)
	elapsed = time.Since(start)
	t.Logf("readBounded of a directory returned after %v", elapsed)
	if err == nil {
		t.Error("readBounded of a directory succeeded")
	}
	if elapsed >= 5*time.Millisecond {
		t.Errorf("readBounded waited %v on a directory", elapsed)
	}
}

// hasFinding reports whether the reader recorded the pair.
func (r *reader) hasFinding(check, subject string) bool {
	return r.seen[Finding{Check: check, Subject: subject}]
}
