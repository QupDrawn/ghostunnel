//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGoTestGroupIsKilled: stopping the go test child kills what it
// started as well, as go test starts a test binary: a shell stands in for
// go test and its background sleep for the binary.
func TestGoTestGroupIsKilled(t *testing.T) {
	resetChildren(t)
	pidFile := filepath.Join(t.TempDir(), "pid")
	cmd := exec.Command("sh", "-c", "sleep 60 & echo $! > "+pidFile+"; wait")
	ownGroup(cmd)
	g := &goTest{cmd: cmd}
	if err := startChild(cmd, g); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()
	var pid int
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if b, err := os.ReadFile(pidFile); err == nil && strings.HasSuffix(string(b), "\n") {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
			break
		}
	}
	if pid == 0 {
		t.Fatal("the shell never started its child")
	}
	stopChildren()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
	}
	t.Fatalf("the shell's child %d outlived stopChildren", pid)
}
