//go:build !unix

package main

// keyprivate_other_test.go proves that a build without POSIX ownership
// fails key-private closed: the probe of this build reports it cannot run,
// and the member, left to that probe, fails the check with this OS as
// subject on an otherwise healthy tree, whatever the key file looks like.

import (
	"errors"
	"runtime"
	"testing"
)

func TestMaterialKeyPrivateUnsupportedHere(t *testing.T) {
	if _, _, err := platformKeyProbe("key.pem"); !errors.Is(err, errKeyProbeUnsupported) {
		t.Fatalf("probe on %s: %v, want errKeyProbeUnsupported", runtime.GOOS, err)
	}
	f := mMaterial(t)
	root := materialTree(t, materialHealthy(f)...)
	checks := MaterialChecks{Live: procLiveness(blTable(t, 4242)), KeyProbe: platformKeyProbe}
	got := materialSorted(checks.Run(&Config{TracesRoot: root, Now: mNow(t)}, &State{}, nil))
	materialWant(t, got, Finding{"key-private", "unsupported-os:" + runtime.GOOS})
}
