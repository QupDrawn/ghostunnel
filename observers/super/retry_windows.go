//go:build windows

package main

// retry_windows.go: on Windows a handle held open on a file by another
// process, without FILE_SHARE_DELETE, blocks a rename or a removal of that
// file for as long as the handle lives: a just-written staging file held
// for an instant by something outside the ring fails its rename over the
// final name, which exits the observer when the file is its own heartbeat
// and, when it is a copy, leaves a staging file behind that raises S3 every
// later cycle. Linux has no such rule, so retry_other.go is the plain call.
// Here a rename or a removal that fails with a sharing or lock violation is
// tried again at a short interval for a bounded budget, well inside the
// cadence; after it the last error is returned unchanged. The same handle
// blocks an open for reading: a scanner holding a freshly written heartbeat
// for an instant makes a whole file unreadable at that instant, which is
// S5. On Linux the same read simply succeeds, so a read of a store or trace
// file is retried the same way (readRetrying, readFile) and after the
// budget fails as the plain call does: a file still present and still
// unreadable is S5. No other error is retried.

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// The budget: retryAttempts tries, retryInterval apart, so at most about
// half a second, well inside the cadence and beside MIN_CYCLE.
const (
	retryAttempts = 50
	retryInterval = 10 * time.Millisecond
)

// The Windows error codes an open handle elsewhere makes a rename or a
// removal fail with.
const (
	errAccessDenied     syscall.Errno = 5
	errSharingViolation syscall.Errno = 32
	errLockViolation    syscall.Errno = 33
)

// sharingError reports whether err is a rename or removal failure
// (*os.LinkError or *os.PathError) whose cause is a sharing violation, a
// lock violation or an access denial.
func sharingError(err error) bool {
	var le *os.LinkError
	var pe *os.PathError
	switch {
	case errors.As(err, &le):
		err = le.Err
	case errors.As(err, &pe):
		err = pe.Err
	default:
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == errSharingViolation || errno == errLockViolation || errno == errAccessDenied
}

// withRetry runs op until it succeeds, fails with something other than a
// sharing violation, or the budget is spent, and returns op's last error
// unchanged.
func withRetry(op func() error) error {
	var err error
	for i := 0; i < retryAttempts; i++ {
		if err = op(); err == nil || !sharingError(err) {
			return err
		}
		if i+1 < retryAttempts {
			time.Sleep(retryInterval)
		}
	}
	return err
}

// renameFile renames old to new, retrying a sharing violation within the
// budget.
func renameFile(old, new string) error {
	return withRetry(func() error { return os.Rename(old, new) })
}

// removeFile removes p, retrying a sharing violation within the budget.
func removeFile(p string) error {
	return withRetry(func() error { return os.Remove(p) })
}

// readRetrying runs read, one open-and-read of a file as a whole, retrying
// a sharing violation within the budget. The whole read is repeated, not
// the open alone: a lock violation can surface on the read of a handle
// that opened, and the bytes must come from one open.
func readRetrying(read func() error) error {
	return withRetry(read)
}

// readFile returns the bytes of the regular file p names (readRegularFile),
// retrying a sharing violation within the budget.
func readFile(p string) ([]byte, error) {
	var data []byte
	err := readRetrying(func() error {
		var err error
		data, err = readRegularFile(p)
		return err
	})
	return data, err
}
