//go:build !unix

package main

// openflags_other.go: outside Unix no file in a directory opens as a named
// pipe that waits for a writer (on Windows a pipe lives in its own
// namespace, \\.\pipe\, and never at a path under the stores or the trace),
// so an open for reading is the plain one; openRegular (encoding.go) holds
// the handle to a regular file, and to the file judged, as it does
// everywhere.

import "os"

// openReadFlags are the flags of every read of a file in the stores or the
// trace (openRegular).
const openReadFlags = os.O_RDONLY
