package main

// keyprivate.go is key-private (SPEC 15): the private key the proxy reports
// as loaded is on disk as a regular file whose permission bits give nobody
// but its owner and, at most, a read to its group, and this observer is
// neither that owner nor in that group. The material member never reads
// the key (materialchecks.go); this is the check that nobody it could stand
// for can either. The rule is over an lstat of the path the start line, or
// the last reload, names: a symbolic link is judged as the link, and a link
// is not a regular file. On a build without POSIX ownership the probe does
// not exist and the check fails closed with the OS as subject; there is no
// flag to accept that, since the key's privacy is not the observer's to
// waive.
//
// Subjects, the first that applies: no-path (the entry names no file);
// unsupported-os:<GOOS>; identity (this process's own ids cannot be read);
// stat (the path cannot be lstat'ed); not-regular; mode:<octal> (any bit
// outside owner read/write and group read: a group write or execute, any
// bit for other, or a set-id or sticky bit); readable-by-observer (owned by
// this observer, or group-readable by a group it is in); none (the material
// list names no key at all: a proxy serving TLS has one, and a list that
// omits it cannot be checked).

import (
	"errors"
	"fmt"
	"runtime"
)

// keyEntry is one lstat of the key's path: whether it exists, whether it
// is a regular file, its owner and group ids and its twelve permission
// bits.
type keyEntry struct {
	Exists  bool
	Regular bool
	UID     uint32
	GID     uint32
	Mode    uint32
}

// keyProbe lstats a path for key-private and says who is asking: this
// process's uid and every group id it holds. An error is the probe being
// unable to run at all (errKeyProbeUnsupported on a build without
// ownership; the identity unreadable), never a path that is absent, which
// is returned as an entry that does not exist.
type keyProbe func(path string) (keyEntry, storeIdentity, error)

// errKeyProbeUnsupported is the probe of a build with no POSIX ownership.
var errKeyProbeUnsupported = errors.New("no key probe on this OS")

// keyModeMask covers every permission bit a private key may not carry:
// the set-user-id, set-group-id and sticky bits, group write and execute,
// and all of other. Owner read and write and group read are what the
// deployment installs (deploy/README: root:gt 0640, the proxy reading
// through its group).
const keyModeMask = 0o7037

// keyPrivateRule judges one entry against who is asking and returns the
// subject it fails with, or "" when the key is private.
func keyPrivateRule(e keyEntry, who storeIdentity) string {
	switch {
	case !e.Exists:
		return "stat"
	case !e.Regular:
		return "not-regular"
	case e.Mode&keyModeMask != 0:
		return fmt.Sprintf("mode:%04o", e.Mode)
	case e.UID == who.UID:
		return "readable-by-observer"
	case e.Mode&0o040 != 0 && groupHeld(e.GID, who.Groups):
		return "readable-by-observer"
	}
	return ""
}

// groupHeld reports whether gid is among groups.
func groupHeld(gid uint32, groups []uint32) bool {
	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

// keyPrivateSubject is key-private for one loaded key entry's path under
// a probe: the subject it fails with, or "" when the key is private.
func keyPrivateSubject(path string, probe keyProbe) string {
	if path == "" {
		return "no-path"
	}
	e, who, err := probe(path)
	switch {
	case errors.Is(err, errKeyProbeUnsupported):
		return "unsupported-os:" + runtime.GOOS
	case err != nil:
		return "identity"
	}
	return keyPrivateRule(e, who)
}
