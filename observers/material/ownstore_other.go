//go:build !linux

package main

// ownstore_other.go is the probe of a build on which the ownership the
// deployment's tree describes does not exist: it collects nothing and says
// so. ownStorePrivateSubjects never reaches it on such a build, because
// the rule fails closed on the OS first (unsupported, or the acceptance);
// it is here so that the comparison compiles everywhere and is proved on
// every host over synthetic entries.

import (
	"errors"
	"os"
)

// probeOwnStore reads nothing on this OS.
func probeOwnStore(*Config) ([]storeEntry, storeIdentity, error) {
	return nil, storeIdentity{}, errors.New("no own-store probe on this OS")
}

// fileOwnerUID knows no owner on this OS. The owner clause of procedure H
// (halts.go, H7) never reaches it, failing on the OS first for any entry
// at all; it is here so that the clause compiles everywhere.
func fileOwnerUID(os.FileInfo) (uint32, error) {
	return 0, errors.New("no file ownership on this OS")
}
