//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package ringtrace

// hasPosixModes is false here: Windows keeps no POSIX permission bits, so
// the mode a test observes says nothing about the mode the code requested.
// The tests then assert the requested mode alone.
const hasPosixModes = false

// setUmask is a no-op where there is no umask.
func setUmask(int) int { return 0 }
