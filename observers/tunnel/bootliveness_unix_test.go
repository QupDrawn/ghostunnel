//go:build unix

package main

// bootliveness_unix_test.go: the start line boot-ambiguous reads of every
// boot is never waited on (openflags_unix_test.go proves the other reads).
// Each of the members that read the trace carries a byte-identical copy of
// this file.

import (
	"os"
	"path/filepath"
	"testing"
)

// A named pipe as a boot's first segment fails that boot's start line at
// once; the boot counts as live, as any unreadable start line does.
func TestBootStartPIDRefusesANamedPipe(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "0000000001")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(dir, gtBootName(1)+".trace")
	fifoAt(t, pipe)
	promptly(t, "bootStartPID", pipe, func() bool {
		_, err := bootStartPID(root, "0000000001", nil)
		return err != nil
	})
}
