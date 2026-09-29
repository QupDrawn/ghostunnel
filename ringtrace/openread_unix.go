//go:build unix

package ringtrace

import (
	"os"

	"golang.org/x/sys/unix"
)

// openRead opens path for reading as readBounded needs it: a symbolic
// link in the final component is not followed (O_NOFOLLOW), and the open
// never waits (O_NONBLOCK), so a named pipe or a device found in the
// file's place is opened at once and refused by the check on the open
// file, instead of holding the caller until a writer appears. On a
// regular file O_NONBLOCK changes nothing about the read.
func openRead(path string) (*os.File, error) {
	for {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
}

// openDir opens the directory path for its sync. O_DIRECTORY refuses
// anything else at the name before it is opened, so a named pipe there is
// an error rather than an open that waits for a writer.
func openDir(path string) (*os.File, error) {
	for {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
}
