//go:build windows

package main

// materialchecks_windows_test.go: trace-readable against a segment held
// open elsewhere without sharing. A hold released within the budget yields
// no finding; a hold outlasting it fails every check through
// trace-readable, as an unreadable segment does.

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMaterialTraceHeldBrieflyIsReadable(t *testing.T) {
	f := mMaterial(t)
	root := materialTree(t, materialHealthy(f)...)
	release := holdExclusive(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	releaseAfter(release, holdFor)
	start := time.Now()
	got := materialRun(t, root)
	elapsed := time.Since(start)
	t.Logf("checks returned after %v (handle held %v)", elapsed, holdFor)
	materialWant(t, got)
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestMaterialTraceHeldPastBudgetIsUnreadable(t *testing.T) {
	f := mMaterial(t)
	root := materialTree(t, materialHealthy(f)...)
	holdExclusive(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	start := time.Now()
	got := materialRun(t, root)
	elapsed := time.Since(start)
	t.Logf("checks gave up after %v (budget %v)", elapsed, readBudget)
	materialWant(t, got, materialAllFail("0000000001/0000000001.trace")...)
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
}
