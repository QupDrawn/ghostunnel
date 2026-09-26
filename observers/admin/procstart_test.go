package main

// procstart_test.go proves proxy-process-alive (procstart.go): the rule
// over an injected reader, the /proc-format reader over a synthetic table
// of the kernel's shape, and the reader this build selects over real child
// processes: a child started now agrees with a start line written now,
// disagrees with one written ten minutes ago or ten minutes hence, and a
// child that is gone is gone. On a build with no reader the same test
// asserts the fail-closed subject instead of skipping.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// procTable writes a process table holding pid with the given start
// offset in ticks and a boot time.
func procTable(t *testing.T, pid int, comm string, ticks int64, btime int64) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, strconv.Itoa(pid)), 0o755); err != nil {
		t.Fatal(err)
	}
	// The kernel's stat line: pid, (comm), state, then the numeric fields,
	// starttime the 22nd.
	line := fmt.Sprintf("%d (%s) S 1 %d %d 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 %d 1000000 200 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid, comm, pid, pid, ticks)
	if err := os.WriteFile(filepath.Join(root, strconv.Itoa(pid), "stat"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if btime >= 0 {
		stat := fmt.Sprintf("cpu  1 2 3 4 5 6 7 8 9 10\nintr 1 2 3\nctxt 100\nbtime %d\nprocesses 500\n", btime)
		if err := os.WriteFile(filepath.Join(root, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func psAt(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func psWant(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("subjects %v, want %v", got, want)
	}
}

func TestProxyProcessAliveRule(t *testing.T) {
	at := psAt(t, "2026-09-24T11:00:00Z")
	startedAt := func(s string) startTimeReader {
		return func(int64) (time.Time, error) { return psAt(t, s), nil }
	}
	psWant(t, proxyProcessAliveSubjects(4242, at, startedAt("2026-09-24T11:00:00Z")))
	psWant(t, proxyProcessAliveSubjects(4242, at, startedAt("2026-09-24T10:59:30Z")))
	psWant(t, proxyProcessAliveSubjects(4242, at, startedAt("2026-09-24T10:58:01Z")))
	psWant(t, proxyProcessAliveSubjects(4242, at, startedAt("2026-09-24T10:57:59Z")), "pid:4242:started-before")
	psWant(t, proxyProcessAliveSubjects(4242, at, startedAt("2026-09-24T11:00:02Z")))
	psWant(t, proxyProcessAliveSubjects(4242, at, startedAt("2026-09-24T11:00:03Z")), "pid:4242:started-after")
	psWant(t, proxyProcessAliveSubjects(4242, at, startedAt("2026-09-24T12:00:00Z")), "pid:4242:started-after")
	// Failures fail closed with the reader's subject, or the pid.
	psWant(t, proxyProcessAliveSubjects(4242, at, func(int64) (time.Time, error) { return time.Time{}, errors.New("gone") }), "pid:4242")
	psWant(t, proxyProcessAliveSubjects(4242, at, func(int64) (time.Time, error) { return time.Time{}, procFail(4242, "access-denied", errors.New("x")) }), "pid:4242:access-denied")
	psWant(t, proxyProcessAliveSubjects(4242, at, unsupportedOSStartTime("plan9")), "unsupported-os:plan9")
}

func TestProcStartTimeReader(t *testing.T) {
	// Boot at 10:00:00; the process started 3600.5 s later: 11:00:00.5.
	btime := psAt(t, "2026-09-24T10:00:00Z").Unix()
	read := procStartTime(procTable(t, 4242, "ghostunnel", 360050, btime))
	started, err := read(4242)
	if err != nil {
		t.Fatal(err)
	}
	if want := psAt(t, "2026-09-24T11:00:00Z").Add(500 * time.Millisecond); !started.Equal(want) {
		t.Fatalf("started %v, want %v", started, want)
	}
	// A command name with spaces and parentheses does not shift the fields.
	read = procStartTime(procTable(t, 4242, "gt (ring) proxy", 360050, btime))
	if got, err := read(4242); err != nil || !got.Equal(started) {
		t.Fatalf("with a strange command name: %v, %v", got, err)
	}
	// Through the rule: the start line written at 11:00:00 agrees; one
	// written at 10:57 does not, nor one at 11:03.
	psWant(t, proxyProcessAliveSubjects(4242, psAt(t, "2026-09-24T11:00:00Z"), read))
	psWant(t, proxyProcessAliveSubjects(4242, psAt(t, "2026-09-24T10:57:00Z"), read), "pid:4242:started-after")
	psWant(t, proxyProcessAliveSubjects(4242, psAt(t, "2026-09-24T11:03:00Z"), read), "pid:4242:started-before")
	// A process that is gone names the pid; a table with no btime, a stat
	// that does not parse, and no table at all are unreadable.
	psWant(t, proxyProcessAliveSubjects(4343, psAt(t, "2026-09-24T11:00:00Z"), read), "pid:4343")
	read = procStartTime(procTable(t, 4242, "ghostunnel", 360050, -1))
	psWant(t, proxyProcessAliveSubjects(4242, psAt(t, "2026-09-24T11:00:00Z"), read), "pid:4242:unreadable")
	root := procTable(t, 4242, "ghostunnel", 360050, btime)
	if err := os.WriteFile(filepath.Join(root, "4242", "stat"), []byte("4242 (ghostunnel) S 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	psWant(t, proxyProcessAliveSubjects(4242, psAt(t, "2026-09-24T11:00:00Z"), procStartTime(root)), "pid:4242:unreadable")
	psWant(t, proxyProcessAliveSubjects(4242, psAt(t, "2026-09-24T11:00:00Z"), procStartTime("")), "pid:4242")
	if _, err := procStatStartTicks([]byte("no parenthesis here")); err == nil {
		t.Fatal("a stat line without a command name parsed")
	}
}

func TestProxyProcessAliveLiveProcess(t *testing.T) {
	read := platformStartTime("/proc")
	child := startCmdlineChild(t, "--keystore", "/etc/gt/keystore.p12")
	gone := startCmdlineChild(t)
	_ = gone.Process.Kill()
	_ = gone.Wait()
	pid, gonePid := int64(child.Process.Pid), int64(gone.Process.Pid)
	now := time.Now().UTC().Truncate(time.Second)
	switch runtime.GOOS {
	case "linux", "windows":
		started, err := read(pid)
		if err != nil {
			t.Fatalf("reading the child's start time: %v", err)
		}
		if d := now.Sub(started); d < -2*time.Second || d > time.Minute {
			t.Fatalf("the child started at %v, now is %v", started, now)
		}
		psWant(t, proxyProcessAliveSubjects(pid, now, read))
		psWant(t, proxyProcessAliveSubjects(pid, now.Add(-10*time.Minute), read), "pid:"+strconv.FormatInt(pid, 10)+":started-after")
		psWant(t, proxyProcessAliveSubjects(pid, now.Add(10*time.Minute), read), "pid:"+strconv.FormatInt(pid, 10)+":started-before")
		psWant(t, proxyProcessAliveSubjects(gonePid, now, read), "pid:"+strconv.FormatInt(gonePid, 10))
		// Through the check, with the build's own readers, on a tree whose
		// start line names the child and was written now.
		lines := adminHealthy()
		lines[0] = aStart(1, now.Format(time.RFC3339), 1, adminConfig(loopback))
		lines[0] = replacePid(t, lines[0], pid)
		lines[1] = aShutdown(2, now.Format(time.RFC3339), "signal", true, "null")
		lines[2] = aShutdown(3, now.Format(time.RFC3339), "status-endpoint", true, `"CN=operator"`)
		checks := AdminChecks{ProcRoot: "/proc", Live: platformLiveness("/proc")}
		checks.StartTime = platformStartTime("/proc")
		// adminTree's fresh tick is dated against adminNow; these lines
		// carry the real clock, so the tick that keeps tick-fresh (and
		// the timestamps in order) is written now as well.
		tree := func(lines []string) string {
			root := t.TempDir()
			gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(aRenumber(append(append([]string{}, lines...), aTick(0, now.Format(time.RFC3339))))...))
			return root
		}
		got := checks.Run(&Config{TracesRoot: tree(lines), Now: now}, &State{}, nil)
		if len(got) != 0 {
			t.Fatalf("a live child that wrote its start line now: %v", got)
		}
		lines[0] = replacePid(t, aStart(1, now.Format(time.RFC3339), 1, adminConfig(loopback)), gonePid)
		got = checks.Run(&Config{TracesRoot: tree(lines), Now: now}, &State{}, nil)
		adminWant(t, got, Finding{"boot-ambiguous", "0000000001:not-live"}, Finding{"cmdline-carries-no-secret", "pid:" + strconv.FormatInt(gonePid, 10)}, Finding{"proxy-process-alive", "pid:" + strconv.FormatInt(gonePid, 10)})
	default:
		want := "unsupported-os:" + runtime.GOOS
		psWant(t, proxyProcessAliveSubjects(pid, now, read), want)
		psWant(t, proxyProcessAliveSubjects(gonePid, now, read), want)
	}
}

func replacePid(t *testing.T, line string, pid int64) string {
	t.Helper()
	i := indexOf(line, `"pid":4242`)
	if i < 0 {
		t.Fatalf("no pid in %q", line)
	}
	return line[:i] + `"pid":` + strconv.FormatInt(pid, 10) + line[i+len(`"pid":4242`):]
}
