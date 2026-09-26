//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A handle held past the whole budget: the sharing violation surfaces
// unchanged, after the budget was spent and not much later.
func TestRenameGivesUpAfterBudget(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "0000000001.hb.tmp")
	final := filepath.Join(dir, "0000000001.hb")
	writeFile(t, tmp, []byte("x"))
	holdExclusive(t, tmp) // released only by the test's cleanup
	budget := time.Duration(retryAttempts-1) * retryInterval
	start := time.Now()
	err := renameFile(tmp, final)
	elapsed := time.Since(start)
	t.Logf("rename gave up after %v (budget %v)", elapsed, budget)
	if err == nil {
		t.Fatal("rename succeeded against a handle that was never released")
	}
	var le *os.LinkError
	if !errors.As(err, &le) {
		t.Fatalf("error is not a *os.LinkError: %T %v", err, err)
	}
	var errno syscall.Errno
	if !errors.As(le.Err, &errno) || errno != errSharingViolation {
		t.Errorf("cause: want ERROR_SHARING_VIOLATION, got %v", le.Err)
	}
	if !sharingError(err) {
		t.Errorf("sharingError does not recognise %v", err)
	}
	if elapsed < budget {
		t.Errorf("gave up after %v, before the budget of %v", elapsed, budget)
	}
	if elapsed > 4*budget {
		t.Errorf("gave up after %v, far beyond the budget of %v", elapsed, budget)
	}
	if _, err := os.Lstat(tmp); err != nil {
		t.Errorf("the staging file is gone although the rename failed: %v", err)
	}
}

// sharingError recognises the three codes under a rename or a removal
// error and nothing else.
func TestSharingErrorClassifies(t *testing.T) {
	yes := []error{
		&os.LinkError{Op: "rename", Old: "a", New: "b", Err: errSharingViolation},
		&os.LinkError{Op: "rename", Old: "a", New: "b", Err: errLockViolation},
		&os.LinkError{Op: "rename", Old: "a", New: "b", Err: errAccessDenied},
		&os.PathError{Op: "remove", Path: "a", Err: errSharingViolation},
		&os.PathError{Op: "remove", Path: "a", Err: errLockViolation},
		&os.PathError{Op: "remove", Path: "a", Err: errAccessDenied},
	}
	for _, err := range yes {
		if !sharingError(err) {
			t.Errorf("not recognised: %v", err)
		}
	}
	no := []error{
		nil,
		errors.New("plain"),
		errSharingViolation, // bare, not from a rename or a removal
		&os.LinkError{Op: "rename", Old: "a", New: "b", Err: syscall.ERROR_FILE_NOT_FOUND},
		&os.PathError{Op: "remove", Path: "a", Err: syscall.ERROR_FILE_NOT_FOUND},
		&os.PathError{Op: "remove", Path: "a", Err: errors.New("no errno")},
	}
	for _, err := range no {
		if sharingError(err) {
			t.Errorf("wrongly recognised: %v", err)
		}
	}
}
