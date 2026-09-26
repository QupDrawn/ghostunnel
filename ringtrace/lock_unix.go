//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package ringtrace

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on f without waiting. The lock
// is tied to the open file description, so a second Open in this process
// conflicts as one in another process does, and the kernel drops it when
// the process dies: no stale lock survives a crash.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
