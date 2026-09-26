package main

// bootliveness.go is boot-ambiguous (SPEC 14.3): the readers judge the
// highest-numbered boot under gt/ and nothing else, so a second proxy
// process, live beside the one whose boot is judged, is a process nobody
// watches. Every boot directory's start line names the pid of the process
// that wrote it; if more than one of those pids is a live process the
// trace is ambiguous about which proxy is the proxy, and the check fails
// with those boots as subject. A boot whose start line cannot be read
// counts as live: it cannot be shown dead.
//
// Liveness is read from the operating system by the probe this build
// selects (liveness_linux.go over the process table, liveness_windows.go
// through the process handle, liveness_other.go failing closed naming the
// OS). Each of the members that read the trace carries its own copy of
// this file and of the probes.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// checkBootAmbiguous is the identifier (SPEC 15). Subject: the boots that
// are live or could not be read, comma-separated in order; or the probe's
// own subject (unsupported-os:<GOOS>) when liveness cannot be read at all.
const checkBootAmbiguous = "boot-ambiguous"

// livenessProbe reports whether the process pid is live. An error that is
// a *livenessError carries the subject the finding gets; any other error
// makes the boot count as live.
type livenessProbe func(pid int64) (bool, error)

// livenessError is a probe's failure with the subject the finding gets.
type livenessError struct {
	Subject string
	Err     error
}

func (e *livenessError) Error() string { return e.Subject + ": " + e.Err.Error() }
func (e *livenessError) Unwrap() error { return e.Err }

// unsupportedOSLiveness is the probe of a build with no facility for
// asking whether another process is live: every probe fails closed naming
// the OS.
func unsupportedOSLiveness(goos string) livenessProbe {
	return func(int64) (bool, error) {
		return false, &livenessError{Subject: "unsupported-os:" + goos, Err: errors.New("no liveness probe for this OS")}
	}
}

// procLiveness is the probe over a process table of the form the Linux
// kernel exposes: <root>/<pid> exists for a live process. It is portable so
// that the rule is proved on every host over a synthetic table; an empty
// root probes nothing and fails.
func procLiveness(root string) livenessProbe {
	return func(pid int64) (bool, error) {
		if root == "" {
			return false, errors.New("no process table configured")
		}
		if pid < 1 {
			return false, nil
		}
		info, err := os.Stat(filepath.Join(root, strconv.FormatInt(pid, 10)))
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		return info.IsDir(), nil
	}
}

// bootStartPID reads the pid the start line of boot name records: the
// first line of its first segment, decoded under every rule of a line. Any
// failure is an error; the caller counts the boot as live.
func bootStartPID(root, name string) (int64, error) {
	f, err := os.Open(filepath.Join(root, name, gtBootName(1)+".trace"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	// Read by the segment rule (gtreader.go): no further than the line
	// bound, since a pre-extended segment whose start line never landed is
	// NUL to its end, and a NUL before the line feed is unwritten space, so
	// the line is not there.
	r := bufio.NewReaderSize(io.LimitReader(f, gtMaxLineBytes+1), 4096)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return 0, err
	}
	if len(line) > gtMaxLineBytes {
		return 0, errors.New("start line exceeds the line bound")
	}
	if bytes.IndexByte(line, 0) >= 0 {
		return 0, errors.New("the first line is not complete")
	}
	rec, err := gtDecodeLine(line[:len(line)-1])
	if err != nil {
		return 0, err
	}
	if rec.Kind != "start" || rec.Start == nil {
		return 0, errors.New("the first line is not a start line")
	}
	return rec.Start.PID, nil
}

// bootAmbiguousFindings takes the boot directories from the root's listing
// (the cycle's one listing of it, shared with the read of the current
// boot), reads each start line's pid and asks the probe about it. Two
// rules, one finding. The highest boot is the one every reader judges, so
// its process must be live: a dead pid there is either a proxy that has
// died, which is a fault whoever else reports it, or a probe that cannot
// see the process (a process table this member is not allowed to read),
// which is the check unable to run and so failing. The subject is that
// boot followed by ":not-live". Then, among every boot, more than one
// live pid is ambiguous about which proxy is the proxy, with those boots
// as subject. The probe is consulted whenever there is a boot at all.
func bootAmbiguousFindings(root string, listing *gtRoot, live livenessProbe) []Finding {
	if listing.Err != nil {
		return nil // trace-readable reports the root
	}
	var boots []string
	for _, de := range listing.Entries {
		if de.IsDir() && gtReBootName.MatchString(de.Name()) {
			boots = append(boots, de.Name())
		}
	}
	sort.Strings(boots)
	if len(boots) == 0 {
		return nil
	}
	highest := boots[len(boots)-1]
	var ambiguous []string
	var findings []Finding
	for _, name := range boots {
		pid, err := bootStartPID(root, name)
		if err != nil {
			ambiguous = append(ambiguous, name) // cannot be shown dead
			continue
		}
		alive, err := live(pid)
		if err != nil {
			var le *livenessError
			if errors.As(err, &le) {
				return []Finding{{Check: checkBootAmbiguous, Subject: le.Subject}}
			}
			ambiguous = append(ambiguous, name) // cannot be shown dead
			continue
		}
		if alive {
			ambiguous = append(ambiguous, name)
		} else if name == highest {
			findings = append(findings, Finding{Check: checkBootAmbiguous, Subject: name + ":not-live"})
		}
	}
	if len(ambiguous) >= 2 {
		findings = append(findings, Finding{Check: checkBootAmbiguous, Subject: strings.Join(ambiguous, ",")})
	}
	return findings
}
