//go:build !linux && !windows

package main

// procstart_other.go is the start-time reader of a build with no facility
// for reading another process's start time: it fails closed, and
// proxy-process-alive fails with subject unsupported-os:<GOOS> on every
// cycle. A build that gains a reader replaces this file with its own and
// nothing else changes.

import "runtime"

// platformStartTime is the reader of this build; procRoot is ignored.
func platformStartTime(string) startTimeReader {
	return unsupportedOSStartTime(runtime.GOOS)
}
