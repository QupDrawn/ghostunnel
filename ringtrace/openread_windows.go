//go:build windows

package ringtrace

import (
	"os"
	"syscall"
)

// openRead opens path for reading as readBounded needs it: a reparse point
// in the final component (a symbolic link, a junction) is opened as itself
// rather than followed (FILE_FLAG_OPEN_REPARSE_POINT), so the check on the
// open file sees what is at the name and refuses anything but a regular
// file. Windows has no named pipe in the filesystem to wait on.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// openDir opens the directory path. Windows has no directory sync, so the
// stores and the emitter never call it there.
func openDir(path string) (*os.File, error) {
	return os.Open(path)
}
