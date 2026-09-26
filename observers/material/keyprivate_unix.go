//go:build unix

package main

// keyprivate_unix.go is the key probe of a build with POSIX ownership: an
// lstat of the path (a symbolic link is judged as the link, which is not a
// regular file), its owner and group ids and its twelve permission bits,
// and who this process runs as.

import (
	"os"
	"syscall"
)

// platformKeyProbe lstats path and returns it with this member's identity.
// An error is returned only when the identity cannot be read; a path that
// cannot be lstat'ed is returned as absent.
func platformKeyProbe(path string) (keyEntry, storeIdentity, error) {
	who := storeIdentity{UID: uint32(os.Getuid())}
	groups, err := os.Getgroups()
	if err != nil {
		return keyEntry{}, who, err
	}
	who.Groups = sortedGroups(append(groups, os.Getgid()))
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return keyEntry{}, who, nil
	}
	mode := uint32(st.Mode)
	return keyEntry{
		Exists:  true,
		Regular: mode&syscall.S_IFMT == syscall.S_IFREG,
		UID:     uint32(st.Uid),
		GID:     uint32(st.Gid),
		Mode:    mode & 0o7777,
	}, who, nil
}
