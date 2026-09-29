//go:build unix

package main

// materialchecks_unix_test.go: the material member's reads of the files
// ghostunnel loaded are never waited on. A named pipe at a material path,
// or put in place of the executable after its Lstat, fails the read at
// once, and the check fails with it.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMaterialReadsRefuseANamedPipe(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "cert.pem")
	fifoAt(t, pipe)
	promptly(t, "readRegular", pipe, func() bool { _, err := readRegular(pipe); return err != nil })
	hash := "0000000000000000000000000000000000000000000000000000000000000000"
	promptly(t, "materialOnDisk", pipe, func() bool {
		return !materialOnDisk(gtMaterial{Material: "cert", Path: pipe, SHA256: &hash}, time.Now(), nil)
	})

	bin := filepath.Join(dir, "ghostunnel")
	if err := os.WriteFile(bin, []byte("a build"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := lstatForRead
	t.Cleanup(func() { lstatForRead = prev; releaseFifo(bin) })
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
	promptly(t, "binaryDigest after the Lstat", bin, func() bool { _, err := binaryDigest(bin); return err != nil })
	if info, err := os.Lstat(bin); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the executable was not replaced by a pipe: %v", err)
	}
}
