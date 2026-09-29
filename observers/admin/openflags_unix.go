//go:build unix

package main

// openflags_unix.go: on a Unix system an open for reading of a named pipe
// waits for a writer, so a pipe put in place of a file between a listing
// or an Lstat and the open would hold the cycle for as long as nobody
// writes to it. O_NONBLOCK makes that open return at once, and openRegular
// (encoding.go) then refuses the handle for not being a regular file. On a
// regular file the flag changes nothing about a read.

import (
	"os"
	"syscall"
)

// openReadFlags are the flags of every read of a file in the stores or the
// trace (openRegular).
const openReadFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC
