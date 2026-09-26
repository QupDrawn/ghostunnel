package main

// cmdline_windows_test.go proves the Windows reader's own boundaries on a
// Windows host: this process reads back as its own argv, a 32-bit process
// fails closed as a bitness mismatch rather than being misread, and a
// process this observer may not open fails closed naming the denial.

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
)

func TestCmdlineWindowsOwnProcess(t *testing.T) {
	read := platformCmdline("")
	argv, err := read(int64(os.Getpid()))
	if runtime.GOARCH == "386" || runtime.GOARCH == "arm" {
		// A 32-bit observer reads nothing: the layout it would walk is not
		// the one it knows.
		if err == nil {
			t.Fatalf("a 32-bit observer read %q", argv)
		}
		if got, want := cmdlineSubject(err, int64(os.Getpid())), "pid:"+strconv.Itoa(os.Getpid())+":bitness-mismatch"; got != want {
			t.Fatalf("subject %q, want %q", got, want)
		}
		return
	}
	if err != nil {
		t.Fatalf("own command line: %v", err)
	}
	if len(argv) != len(os.Args) {
		t.Fatalf("own argv read back as %q, os.Args is %q", argv, os.Args)
	}
	for i := 1; i < len(argv); i++ {
		if argv[i] != os.Args[i] {
			t.Fatalf("own argv[%d] read back as %q, want %q", i, argv[i], os.Args[i])
		}
	}
}

func TestCmdlineWindowsBitnessMismatch(t *testing.T) {
	if runtime.GOARCH == "386" || runtime.GOARCH == "arm" {
		return // the own-process test above covers the 32-bit observer
	}
	// A 32-bit child: the WOW64 command interpreter, held open on its
	// standard input until the test ends.
	cmd := exec.Command(`C:\Windows\SysWOW64\cmd.exe`, "/c", "set /p x=")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = stdin.Close()
	})
	pid := int64(cmd.Process.Pid)
	argv, err := platformCmdline("")(pid)
	if err == nil {
		t.Fatalf("a 32-bit process read as %q", argv)
	}
	if got, want := cmdlineSubject(err, pid), "pid:"+strconv.FormatInt(pid, 10)+":bitness-mismatch"; got != want {
		t.Fatalf("subject %q, want %q (%v)", got, want, err)
	}
}

func TestCmdlineWindowsAccessDenied(t *testing.T) {
	// Pid 4 is the System process, which no user-mode process may open
	// for reading memory; the reader must say so rather than guess.
	argv, err := platformCmdline("")(4)
	if err == nil {
		t.Fatalf("the System process read as %q", argv)
	}
	if got, want := cmdlineSubject(err, 4), "pid:4:access-denied"; got != want {
		t.Fatalf("subject %q, want %q (%v)", got, want, err)
	}
}
