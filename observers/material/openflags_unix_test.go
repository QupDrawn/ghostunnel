//go:build unix

package main

// openflags_unix_test.go proves that no read of a file by this member waits
// on a named pipe: a pipe at the path, or put in place of a regular file
// between the Lstat that judged it and the open, makes the read fail at
// once. Every member carries a byte-identical copy of this file.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fifoAt makes a named pipe at p, and releases, when the test ends, any
// read left waiting on it: an open for writing lets a waiting open for
// reading return, and the close then ends its read.
func fifoAt(t *testing.T, p string) {
	t.Helper()
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	t.Cleanup(func() { releaseFifo(p) })
}

func releaseFifo(p string) {
	if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		f.Close()
	}
}

// promptly runs read and fails unless it returns within a few seconds with
// refused true: a read that waits on the pipe is the failure being proved
// absent, and is released so that the test binary can end.
func promptly(t *testing.T, name, pipe string, read func() (refused bool)) {
	t.Helper()
	done := make(chan bool, 1)
	go func() { done <- read() }()
	select {
	case refused := <-done:
		if !refused {
			t.Errorf("%s: a named pipe was read as a file", name)
		}
	case <-time.After(5 * time.Second):
		releaseFifo(pipe)
		t.Errorf("%s: the read waited on a named pipe", name)
	}
}

// TestReadsRefuseANamedPipe: every read a member makes of a file (the
// bounded read of procedures C, H, K and V, the classification prefix of a
// stray, the whole read of I5, the driver and the traces, the segment read
// and the start line of boot-ambiguous, the stored chain or CA bundle of
// the substance rules) returns at once with nothing when a named pipe is
// where the file was.
func TestReadsRefuseANamedPipe(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe")
	fifoAt(t, pipe)

	promptly(t, "readFile", pipe, func() bool { _, err := readFile(pipe); return err != nil })
	promptly(t, "readPrefix", pipe, func() bool { return readPrefix(pipe) == nil })
	promptly(t, "gtReadSegment", pipe, func() bool { _, err := gtReadSegment(pipe, 0); return err != nil })
	promptly(t, "readBounded", pipe, func() bool { _, _, err := readBounded(pipe, 4096); return err != nil })
	promptly(t, "substanceReadStored", pipe, func() bool { _, err := substanceReadStored(pipe, "pipe", substanceMaxChainBytes); return err != nil })

	// The pipe put in place of a regular file after the Lstat judged it.
	swapped := filepath.Join(dir, "0000000001.hb")
	if err := os.WriteFile(swapped, []byte(`{"kind":"heartbeat",}`), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := lstatForRead
	t.Cleanup(func() { lstatForRead = prev; releaseFifo(swapped) })
	lstatForRead = func(p string) (os.FileInfo, error) {
		info, err := prev(p)
		if err == nil && info.Mode().IsRegular() {
			if err := os.Remove(p); err != nil {
				return nil, err
			}
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				return nil, err
			}
		}
		return info, err
	}
	promptly(t, "readBounded after the Lstat", swapped, func() bool {
		_, oversized, err := readBounded(swapped, 4096)
		return err != nil && !oversized
	})
	if info, err := os.Lstat(swapped); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the regular file was not replaced by a pipe: %v", err)
	}

	// The same for a file of the chain store, read by the substance rules.
	chain := []byte("chain")
	stored := filepath.Join(dir, substanceHash(chain)+".der")
	if err := os.WriteFile(stored, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { releaseFifo(stored) })
	promptly(t, "substanceReadStored after the Lstat", stored, func() bool {
		data, err := substanceReadStored(stored, substanceHash(chain), substanceMaxChainBytes)
		return err != nil && data == nil
	})
	if info, err := os.Lstat(stored); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the stored file was not replaced by a pipe: %v", err)
	}
}
