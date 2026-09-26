package main

// procstart.go is proxy-process-alive: the start line names a pid, and a
// pid is reused, so a process by that number is not yet the process that
// wrote the line. The one that did started before it wrote, and not long
// before: its start time, as the operating system records it, must not be
// after the start line's `at` and must not be more than procStartBefore
// before it. The start time is read by the reader this build selects
// (procstart_linux.go from the process table, procstart_windows.go
// through the process handle, procstart_other.go failing closed naming the
// OS); the /proc-format reader (procStartTime) is portable so that its
// rules are proved on every host over a synthetic table. Every read
// failure fails closed with a subject that says why.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// checkProxyProcessAlive is the identifier (SPEC 15). Subject: "pid:<pid>"
// when no such process exists; "pid:<pid>:started-after" when it started
// after the start line's `at` (past the slack); "pid:<pid>:started-before"
// when it started more than procStartBefore before it;
// "pid:<pid>:unreadable" when its start time cannot be read or parsed;
// "pid:<pid>:access-denied" for a process this observer may not open;
// "unsupported-os:<GOOS>" on a build with no reader.
const checkProxyProcessAlive = "proxy-process-alive"

const (
	// procStartBefore is how long before the start line's `at` the
	// process may have started: the time from exec to the first trace
	// line, generously.
	procStartBefore = 120 * time.Second
	// procStartSlack is the slack on the other side, for the precisions
	// involved: `at` is a whole second, the process table's boot time is a
	// whole second and its start offset a hundredth, so a process started
	// inside the second the line was written reads as started after it by
	// up to a second each way.
	procStartSlack = 2 * time.Second
	// procTicksPerSecond is USER_HZ, the unit of the process table's start
	// offset: a fixed kernel ABI of 100 on every Linux.
	procTicksPerSecond = 100
)

// startTimeReader returns when the process pid started, or an error. An
// error that is a *procError carries its own bounded subject; any other
// names the pid alone, which is what a process that is gone gets.
type startTimeReader func(pid int64) (time.Time, error)

// procError is a reader's failure with the subject the finding gets.
type procError struct {
	Subject string
	Err     error
}

func (e *procError) Error() string { return e.Subject + ": " + e.Err.Error() }
func (e *procError) Unwrap() error { return e.Err }

// procSubject is the finding subject for a reader's error.
func procSubject(err error, pid int64) string {
	var e *procError
	if errors.As(err, &e) {
		return e.Subject
	}
	return "pid:" + strconv.FormatInt(pid, 10)
}

// procFail is a reader's failure about pid with the given cause.
func procFail(pid int64, what string, err error) error {
	return &procError{Subject: fmt.Sprintf("pid:%d:%s", pid, what), Err: err}
}

// unsupportedOSStartTime is the reader of a build with no facility for
// reading another process's start time: every read fails closed naming
// the OS.
func unsupportedOSStartTime(goos string) startTimeReader {
	return func(int64) (time.Time, error) {
		return time.Time{}, &procError{Subject: "unsupported-os:" + goos, Err: errors.New("no start-time reader for this OS")}
	}
}

// proxyProcessAliveSubjects is the rule: the subjects the check fails
// with, none when it passes, for the pid and `at` of a start line over a
// reader.
func proxyProcessAliveSubjects(pid int64, at time.Time, read startTimeReader) []string {
	started, err := read(pid)
	if err != nil {
		return []string{procSubject(err, pid)}
	}
	var out []string
	if started.After(at.Add(procStartSlack)) {
		out = append(out, fmt.Sprintf("pid:%d:started-after", pid))
	}
	if started.Before(at.Add(-procStartBefore)) {
		out = append(out, fmt.Sprintf("pid:%d:started-before", pid))
	}
	return out
}

// procStartTime is the reader over a process table of the form the Linux
// kernel exposes: <root>/<pid>/stat, whose field 22 is the process's start
// time in USER_HZ ticks since boot, and <root>/stat, whose btime line is
// the boot time in seconds since the epoch. An empty root reads nothing;
// a process directory that is missing is a process that is gone.
func procStartTime(root string) startTimeReader {
	return func(pid int64) (time.Time, error) {
		if root == "" {
			return time.Time{}, errors.New("no process table configured")
		}
		if pid < 1 {
			return time.Time{}, errors.New("pid below 1")
		}
		stat, err := os.ReadFile(filepath.Join(root, strconv.FormatInt(pid, 10), "stat"))
		if err != nil {
			if os.IsNotExist(err) {
				return time.Time{}, err
			}
			return time.Time{}, procFail(pid, "unreadable", err)
		}
		ticks, err := procStatStartTicks(stat)
		if err != nil {
			return time.Time{}, procFail(pid, "unreadable", err)
		}
		btime, err := procBootTime(root)
		if err != nil {
			return time.Time{}, procFail(pid, "unreadable", err)
		}
		return time.Unix(btime+ticks/procTicksPerSecond, (ticks%procTicksPerSecond)*(int64(time.Second)/procTicksPerSecond)).UTC(), nil
	}
}

// procStatStartTicks is field 22 of a stat line. The second field, the
// command name in parentheses, may hold spaces and parentheses, so the
// fields are counted from the last closing parenthesis: the state is field
// 3 and the first after it.
func procStatStartTicks(stat []byte) (int64, error) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, errors.New("stat: no command name")
	}
	fields := strings.Fields(string(stat[end+1:]))
	const startTimeField = 22
	if len(fields) < startTimeField-2 {
		return 0, fmt.Errorf("stat: %d fields after the command name, want at least %d", len(fields), startTimeField-2)
	}
	ticks, err := strconv.ParseInt(fields[startTimeField-3], 10, 64)
	if err != nil || ticks < 0 {
		return 0, fmt.Errorf("stat: start time %q is not a tick count", fields[startTimeField-3])
	}
	return ticks, nil
}

// procBootTime is the btime line of <root>/stat.
func procBootTime(root string) (int64, error) {
	f, err := os.Open(filepath.Join(root, "stat"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == "btime" {
			n, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("stat: btime %q is not a time", fields[1])
			}
			return n, nil
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("stat: no btime line")
}
