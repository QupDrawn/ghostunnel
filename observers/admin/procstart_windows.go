//go:build windows

package main

// procstart_windows.go reads another process's start time the way Windows
// keeps it: the creation time GetProcessTimes reports for a handle opened
// for limited query. Only the standard library's syscall package is used.
// A pid the system does not know (ERROR_INVALID_PARAMETER), or one whose
// process has exited while something still holds its handle, is a process
// that is gone and names the pid alone; a process this observer may not
// open fails closed as access denied; any other failure as unreadable.

import (
	"errors"
	"syscall"
	"time"
)

const (
	procQueryLimitedInformation = 0x1000
	// procStillActive is the exit code of a process that has not exited.
	procStillActive = 259
	// procInvalidParameter is ERROR_INVALID_PARAMETER: no such process.
	procInvalidParameter syscall.Errno = 87
)

// platformStartTime is the reader of this build; procRoot is ignored.
func platformStartTime(string) startTimeReader {
	return readWindowsStartTime
}

func readWindowsStartTime(pid int64) (time.Time, error) {
	if pid < 1 || pid > 0xFFFFFFFF {
		return time.Time{}, errors.New("pid out of range")
	}
	h, err := syscall.OpenProcess(procQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		switch err {
		case procInvalidParameter:
			return time.Time{}, err
		case syscall.ERROR_ACCESS_DENIED:
			return time.Time{}, procFail(pid, "access-denied", err)
		}
		return time.Time{}, procFail(pid, "unreadable", err)
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return time.Time{}, procFail(pid, "unreadable", err)
	}
	if code != procStillActive {
		return time.Time{}, errors.New("the process has exited")
	}
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, procFail(pid, "unreadable", err)
	}
	return time.Unix(0, creation.Nanoseconds()).UTC(), nil
}
