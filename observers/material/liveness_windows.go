//go:build windows

package main

// liveness_windows.go asks Windows whether a process is live the way the
// system answers it: a handle opened for limited query and the exit code
// it reports, STILL_ACTIVE for a process that has not exited. Only the
// standard library's syscall package is used. A pid the system does not
// know (ERROR_INVALID_PARAMETER) is not live; a process this observer may
// not open exists and is counted live, because it cannot be shown dead;
// any other failure is an error and the boot counts as live too.

import "syscall"

const (
	processQueryLimitedInformation = 0x1000
	// stillActive is the exit code GetExitCodeProcess reports for a
	// process that has not exited (STATUS_PENDING).
	stillActive = 259
	// errInvalidParameter is what OpenProcess fails with for a pid the
	// system does not know (ERROR_INVALID_PARAMETER).
	errInvalidParameter syscall.Errno = 87
)

// platformLiveness is the probe of this build; procRoot is ignored.
func platformLiveness(string) livenessProbe {
	return windowsLiveness
}

func windowsLiveness(pid int64) (bool, error) {
	if pid < 1 || pid > 0xFFFFFFFF {
		return false, nil
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		switch err {
		case errInvalidParameter:
			return false, nil
		case syscall.ERROR_ACCESS_DENIED:
			return true, nil
		}
		return false, err
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false, err
	}
	return code == stillActive, nil
}
