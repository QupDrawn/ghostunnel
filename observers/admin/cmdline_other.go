//go:build !linux && !windows

package main

// cmdline_other.go is the reader of a build with no facility for reading
// another process's command line: it fails closed, and
// cmdline-carries-no-secret fails with subject unsupported-os:<GOOS> on
// every cycle. A check that cannot run has not passed; a build that gains a
// reader replaces this file with its own and nothing else changes.

import "runtime"

// platformCmdline is the reader of this build; procRoot is ignored.
func platformCmdline(string) cmdlineReader {
	return unsupportedOSCmdline(runtime.GOOS)
}
