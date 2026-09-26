//go:build !windows

package main

import "testing"

// holdExclusive has no counterpart outside Windows: no open handle blocks a
// read, a rename or a removal there. A test that needs one is skipped.
func holdExclusive(t *testing.T, p string) (release func()) {
	t.Helper()
	t.Skip("an exclusive open exists only on Windows")
	return func() {}
}
