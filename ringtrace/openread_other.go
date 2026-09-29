//go:build !unix && !windows

package ringtrace

import "os"

// openRead opens path for reading. This platform has no open that refuses
// to follow a link or to wait; the check on the open file that
// readBounded makes still refuses anything but the regular file the
// lstat found.
func openRead(path string) (*os.File, error) {
	return os.Open(path)
}

// openDir opens the directory path for its sync.
func openDir(path string) (*os.File, error) {
	return os.Open(path)
}
