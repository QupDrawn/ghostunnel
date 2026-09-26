//go:build windows

package main

// tunnelchecks_windows_test.go: trace-readable against a segment held open
// elsewhere without sharing. A hold released within the budget yields no
// finding; a hold outlasting it fails every check through trace-readable,
// as an unreadable segment does.

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTunnelTraceHeldBrieflyIsReadable(t *testing.T) {
	root := tunnelTree(t, tunnelHealthy()...)
	release := holdExclusive(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	releaseAfter(release, holdFor)
	start := time.Now()
	got := tunnelRun(t, root, TunnelChecks{})
	elapsed := time.Since(start)
	t.Logf("checks returned after %v (handle held %v)", elapsed, holdFor)
	tunnelWant(t, got)
	if elapsed < holdFor {
		t.Errorf("returned before the handle was released: %v", elapsed)
	}
	if elapsed >= readBudget {
		t.Errorf("waited the whole budget (%v) although the handle was released after %v", elapsed, holdFor)
	}
}

func TestTunnelTraceHeldPastBudgetIsUnreadable(t *testing.T) {
	root := tunnelTree(t, tunnelHealthy()...)
	holdExclusive(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	start := time.Now()
	got := tunnelRun(t, root, TunnelChecks{})
	elapsed := time.Since(start)
	t.Logf("checks gave up after %v (budget %v)", elapsed, readBudget)
	tunnelWant(t, got, tunnelAllFail("0000000001/0000000001.trace")...)
	if elapsed < readBudget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, readBudget)
	}
}
