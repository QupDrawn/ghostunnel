//go:build !windows

package main

// retry_other.go: only Windows lets an open handle block a rename, a
// removal or a read (retry_windows.go). Everywhere else these are the calls
// themselves, with no retry and no sleep.

import "os"

// renameFile renames old to new.
func renameFile(old, new string) error {
	return os.Rename(old, new)
}

// removeFile removes p.
func removeFile(p string) error {
	return os.Remove(p)
}

// readRetrying runs read once.
func readRetrying(read func() error) error {
	return read()
}

// readFile returns the bytes of the regular file p names (readRegularFile).
func readFile(p string) ([]byte, error) {
	return readRegularFile(p)
}
