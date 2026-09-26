//go:build windows

package main

// gtreader_windows_test.go: a segment of gt/ held open elsewhere without
// sharing, as the writer's own scanner may hold it for an instant. A hold
// released within the budget reads as if it had never been there; a hold
// outlasting the budget is the unreadable segment it always was. Every
// member that reads gt/ carries a byte-identical copy of this file.

import (
	"path/filepath"
	"testing"
	"time"
)

func TestGTSegmentHeldBrieflyIsRead(t *testing.T) {
	root := gtOneBoot(t, gtLines...)
	release := holdExclusive(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	releaseAfter(release, holdFor)
	start := time.Now()
	b, err := gtReadLatest(root)
	elapsed := time.Since(start)
	t.Logf("gtReadLatest returned after %v (handle held %v)", elapsed, holdFor)
	if err != nil {
		t.Fatalf("gtReadLatest against a handle released after %v: %v", holdFor, err)
	}
	if len(b.Records) != len(gtLines) {
		t.Errorf("records: got %d, want %d", len(b.Records), len(gtLines))
	}
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestGTSegmentHeldPastBudgetFails(t *testing.T) {
	root := gtOneBoot(t, gtLines...)
	holdExclusive(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	start := time.Now()
	_, err := gtReadLatest(root)
	elapsed := time.Since(start)
	t.Logf("gtReadLatest gave up after %v (budget %v)", elapsed, readBudget)
	if err == nil {
		t.Fatal("gtReadLatest succeeded against a handle that was never released")
	}
	if got, want := gtSubject(err), "0000000001/0000000001.trace"; got != want {
		t.Errorf("subject: got %q, want %q", got, want)
	}
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
	if elapsed > 4*readBudget {
		t.Errorf("gave up after %v, far beyond the budget of %v", elapsed, readBudget)
	}
}
