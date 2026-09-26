//go:build linux

package main

// cmdline_linux.go selects the reader of a Linux build: the kernel exposes
// every process's command line as <ProcRoot>/<pid>/cmdline (cmdline_proc.go),
// and -proc names that root, /proc by default. This is the only build on
// which the flag means anything.

// platformCmdline is the reader of this build.
func platformCmdline(procRoot string) cmdlineReader {
	return procCmdline(procRoot)
}
