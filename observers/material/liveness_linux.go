//go:build linux

package main

// liveness_linux.go selects the probe of a Linux build: the kernel exposes
// every live process as <ProcRoot>/<pid> (bootliveness.go, procLiveness),
// and -proc names that root, /proc by default. This is the only build on
// which the flag means anything.

// platformLiveness is the probe of this build.
func platformLiveness(procRoot string) livenessProbe {
	return procLiveness(procRoot)
}
