//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package ringtrace

import "syscall"

// hasPosixModes is whether the operating system reports the permission
// bits a file was created with: on these platforms the mode observed is
// the mode requested less the umask, so a test can assert what landed.
const hasPosixModes = true

// setUmask sets the process umask and returns the previous one.
func setUmask(mask int) int { return syscall.Umask(mask) }
