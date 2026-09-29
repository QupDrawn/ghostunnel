//go:build !unix

package main

// openflags_other_test.go: openflags_unix_test.go has no counterpart outside
// Unix. Every member carries a byte-identical copy of this file.

import "testing"

// TestReadsRefuseANamedPipe is proved on Unix only.
func TestReadsRefuseANamedPipe(t *testing.T) {
	t.Skip("no named pipe can be put at a path here: Windows keeps pipes in their own namespace, \\\\.\\pipe\\, never in a directory of the stores or the trace (openflags_other.go)")
}
