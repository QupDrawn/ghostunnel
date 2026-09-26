//go:build linux

package main

// procstart_linux.go selects the start-time reader of a Linux build: the
// kernel exposes every process's start time as <ProcRoot>/<pid>/stat
// field 22 against the boot time in <ProcRoot>/stat (procstart.go,
// procStartTime), and -proc names that root, /proc by default.

// platformStartTime is the reader of this build.
func platformStartTime(procRoot string) startTimeReader {
	return procStartTime(procRoot)
}
