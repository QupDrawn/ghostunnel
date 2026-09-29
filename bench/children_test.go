package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestHelperSleeper is not a test: run as a child with BENCH_HELPER_SLEEP
// set, it sleeps, standing in for a proxy that would outlive the tool.
func TestHelperSleeper(t *testing.T) {
	if os.Getenv("BENCH_HELPER_SLEEP") == "" {
		t.Skip("helper process")
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

func sleeperArgs() []string { return []string{"-test.run=^TestHelperSleeper$"} }

// resetChildren gives a test a registry of its own.
func resetChildren(t *testing.T) {
	children.Lock()
	children.set, children.stopping = map[child]struct{}{}, false
	children.Unlock()
	t.Cleanup(func() {
		stopChildren()
		children.Lock()
		children.set, children.stopping = map[child]struct{}{}, false
		children.Unlock()
	})
}

// TestStopChildrenStopsEveryProxy: what an interrupt runs stops every proxy
// still running, and none is left registered.
func TestStopChildrenStopsEveryProxy(t *testing.T) {
	resetChildren(t)
	t.Setenv("BENCH_HELPER_SLEEP", "1")
	dir := t.TempDir()
	var procs []*proxyProc
	for _, name := range []string{"base", "fork"} {
		p, err := startProxy(os.Args[0], filepath.Join(dir, name+".log"), sleeperArgs(), "", "")
		if err != nil {
			t.Fatal(err)
		}
		procs = append(procs, p)
	}
	stopChildren()
	for _, p := range procs {
		select {
		case <-p.exited:
		case <-time.After(5 * time.Second):
			t.Fatalf("proxy %d still running after stopChildren", p.cmd.Process.Pid)
		}
	}
	children.Lock()
	n := len(children.set)
	children.Unlock()
	if n != 0 {
		t.Fatalf("%d children still registered", n)
	}
}

// TestNothingStartsOnceStopping: a proxy the run would start after the
// interrupt is refused, not left behind.
func TestNothingStartsOnceStopping(t *testing.T) {
	resetChildren(t)
	t.Setenv("BENCH_HELPER_SLEEP", "1")
	stopChildren()
	p, err := startProxy(os.Args[0], filepath.Join(t.TempDir(), "late.log"), sleeperArgs(), "", "")
	if !errors.Is(err, errStopping) {
		if p != nil {
			p.stop()
		}
		t.Fatalf("startProxy after stopChildren = %v, want errStopping", err)
	}
}

// TestGoTestIsStopped: the -gobench go test is a child too, and an
// interrupt stops it (what it started: TestGoTestGroupIsKilled, unix).
func TestGoTestIsStopped(t *testing.T) {
	resetChildren(t)
	t.Setenv("BENCH_HELPER_SLEEP", "1")
	cmd := exec.Command(os.Args[0], sleeperArgs()...)
	ownGroup(cmd)
	g := &goTest{cmd: cmd}
	if err := startChild(cmd, g); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopChildren()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("go test child still running after stopChildren")
	}
}
