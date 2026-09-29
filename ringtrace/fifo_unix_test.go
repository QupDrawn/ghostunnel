//go:build unix

package ringtrace

import (
	"os"

	"golang.org/x/sys/unix"
)

// mkfifo makes a named pipe at path; noFIFO is empty where it can.
func mkfifo(path string) error { return unix.Mkfifo(path, 0o644) }

const noFIFO = ""

// releaseFIFO opens the pipe at path for writing without waiting, which
// completes an open for reading that is waiting on it.
func releaseFIFO(path string) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		os.NewFile(uintptr(fd), path).Close()
	}
}
