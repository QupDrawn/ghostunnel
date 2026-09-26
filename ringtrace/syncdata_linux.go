//go:build linux

package ringtrace

import (
	"os"
	"syscall"
)

// syncData makes a segment's written data durable with fdatasync: the data
// and every piece of metadata needed to read it back (the size, the block
// mapping), leaving out what is not (the timestamps, which nothing in the
// ring reads of a segment). On ext4 an fsync after a quiet moment journals
// the inode the write's timestamp dirtied, which fdatasync skips, so an
// append into a pre-extended segment commits several times faster. Size
// changes (the pre-extension at open, the truncation at close) are synced
// with fsync, in the emitter.
func syncData(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.Fdatasync(int(fd)) }); err != nil {
		return err
	}
	return serr
}
