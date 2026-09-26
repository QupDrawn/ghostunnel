//go:build !unix

package main

// keyprivate_other.go is the key probe of a build on which the ownership
// key-private judges does not exist: it reads nothing and says so, and the
// check fails closed with the OS as subject (keyPrivateSubject). Windows
// has ACLs, which this build does not read; a build that gains a reader
// of them replaces this file with its own and nothing else changes.

// platformKeyProbe reads nothing on this OS.
func platformKeyProbe(string) (keyEntry, storeIdentity, error) {
	return keyEntry{}, storeIdentity{}, errKeyProbeUnsupported
}
