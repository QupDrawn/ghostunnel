//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package ringtrace

import (
	"errors"
	"os"
)

// lockFile has no exclusive lock facility on this platform, so an emitter
// cannot be made the only one under a root, and Open fails closed rather
// than run unlocked.
func lockFile(f *os.File) error {
	return errors.New("no exclusive file lock facility on this platform")
}

func unlockFile(f *os.File) error {
	return nil
}
