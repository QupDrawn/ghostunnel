package main

// cmdline_test.go proves the command-line reader behind
// cmdline-carries-no-secret on the host the tests run on: a child process
// started with a command line the test knows is read back as that argv
// through the reader the build selected (cmdline_linux.go,
// cmdline_windows.go), with no opt-in and no flag; the check fires on it
// with the right subject; a child with nothing on its command line passes;
// and a process that is gone fails closed. On a build with no reader
// (cmdline_other.go) the same test asserts the fail-closed subject instead
// of skipping: a host this cannot run on is a host the check fails on.

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCmdlineHelperProcess is not a test of anything: re-executed by
// startCmdlineChild as a child process with a known command line, it
// sleeps until it is killed. Run directly it does nothing.
func TestCmdlineHelperProcess(t *testing.T) {
	if os.Getenv("GT_ADMIN_CMDLINE_HELPER") != "1" {
		return
	}
	time.Sleep(time.Minute)
}

// startCmdlineChild starts this test binary as a child whose command line
// ends in extra, and kills it when the test ends.
func startCmdlineChild(t *testing.T, extra ...string) *exec.Cmd {
	t.Helper()
	args := append([]string{"-test.run=^TestCmdlineHelperProcess$", "--"}, extra...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GT_ADMIN_CMDLINE_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

// adminTreeForPid is a healthy tree whose start line names pid.
func adminTreeForPid(t *testing.T, pid int) string {
	t.Helper()
	lines := adminHealthy()
	lines[0] = strings.Replace(lines[0], `"pid":4242`, `"pid":`+strconv.Itoa(pid), 1)
	return adminTree(t, lines...)
}

func TestCmdlineLiveProcess(t *testing.T) {
	read := platformCmdline("/proc")
	secret := startCmdlineChild(t, "--storepass=s3cret", "--metrics-url", "https://user:pw@metrics.example/push")
	clean := startCmdlineChild(t, "--keystore", "/etc/gt/keystore.p12")
	gone := startCmdlineChild(t)
	_ = gone.Process.Kill()
	_ = gone.Wait()
	secretPid, cleanPid, gonePid := secret.Process.Pid, clean.Process.Pid, gone.Process.Pid
	goneSubject := "pid:" + strconv.Itoa(gonePid)

	switch runtime.GOOS {
	case "linux", "windows":
		argv, err := read(int64(secretPid))
		if err != nil {
			t.Fatalf("reading the child's command line: %v", err)
		}
		if len(argv) < 4 || argv[0] == "" {
			t.Fatalf("argv read back as %q", argv)
		}
		tail := argv[len(argv)-3:]
		if tail[0] != "--storepass=s3cret" || tail[1] != "--metrics-url" || tail[2] != "https://user:pw@metrics.example/push" {
			t.Fatalf("argv tail read back as %q", tail)
		}
		if argv, err := read(int64(cleanPid)); err != nil || len(argv) < 2 || argv[len(argv)-1] != "/etc/gt/keystore.p12" {
			t.Fatalf("clean child read back as %q, %v", argv, err)
		}
		if argv, err := read(int64(gonePid)); err == nil {
			t.Fatalf("a process that is gone read back as %q", argv)
		} else if got := cmdlineSubject(err, int64(gonePid)); got != goneSubject {
			t.Fatalf("a process that is gone has subject %q, want %q (%v)", got, goneSubject, err)
		}
		// Through the check, with nothing injected: the build's own
		// reader, as the deployed observer runs it.
		adminWant(t, adminRun(t, adminTreeForPid(t, secretPid), AdminChecks{ProcRoot: "/proc", Live: platformLiveness("/proc")}), Finding{"cmdline-carries-no-secret", "--storepass"}, Finding{"cmdline-carries-no-secret", "url-credentials"})
		adminWant(t, adminRun(t, adminTreeForPid(t, cleanPid), AdminChecks{ProcRoot: "/proc", Live: platformLiveness("/proc")}))
		adminWant(t, adminRun(t, adminTreeForPid(t, gonePid), AdminChecks{ProcRoot: "/proc", Live: platformLiveness("/proc")}), Finding{"boot-ambiguous", "0000000001:not-live"}, Finding{"cmdline-carries-no-secret", goneSubject})
	default:
		want := "unsupported-os:" + runtime.GOOS
		for _, pid := range []int{secretPid, cleanPid, gonePid} {
			if argv, err := read(int64(pid)); err == nil {
				t.Fatalf("a build with no reader read %q", argv)
			} else if got := cmdlineSubject(err, int64(pid)); got != want {
				t.Fatalf("subject %q, want %q", got, want)
			}
			// The build's liveness probe names the OS the same way.
			adminWant(t, adminRun(t, adminTreeForPid(t, pid), AdminChecks{ProcRoot: "/proc", Live: platformLiveness("/proc")}), Finding{"boot-ambiguous", want}, Finding{"cmdline-carries-no-secret", want})
		}
	}
}

// TestCmdlineReaderFailsClosed is the check over an injected reader: a
// reader with no facility for this OS names the OS, any other failure or
// an empty command line names the pid, and what a reader returns is judged
// by the same rules as a process table.
func TestCmdlineReaderFailsClosed(t *testing.T) {
	root := adminTree(t, adminHealthy()...)
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: unsupportedOSCmdline("plan9")}), Finding{"cmdline-carries-no-secret", "unsupported-os:plan9"})
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: func(int64) ([]string, error) { return nil, errors.New("boom") }}), Finding{"cmdline-carries-no-secret", "pid:4242"})
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: func(int64) ([]string, error) { return nil, nil }}), Finding{"cmdline-carries-no-secret", "pid:4242"})
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: func(int64) ([]string, error) { return []string{"ghostunnel", "--pkcs11-pin", "1234"}, nil }}), Finding{"cmdline-carries-no-secret", "--pkcs11-pin"})
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: func(int64) ([]string, error) { return []string{"ghostunnel", "server"}, nil }}))
	// A reader's own bounded subject is carried as it is.
	adminWant(t, adminRun(t, root, AdminChecks{Cmdline: func(int64) ([]string, error) {
		return nil, &cmdlineError{Subject: "pid:4242:access-denied", Err: errors.New("access denied")}
	}}), Finding{"cmdline-carries-no-secret", "pid:4242:access-denied"})
}
