//go:build !linux && !windows

package main

// liveness_other.go is the probe of a build with no facility for asking
// whether another process is live: it fails closed, and boot-ambiguous
// fails with subject unsupported-os:<GOOS> whenever there is more than one
// boot to tell apart. A build that gains a probe replaces this file with
// its own and nothing else changes.

import "runtime"

// platformLiveness is the probe of this build; procRoot is ignored.
func platformLiveness(string) livenessProbe {
	return unsupportedOSLiveness(runtime.GOOS)
}
