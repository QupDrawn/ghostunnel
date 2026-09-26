package main

// keyprivate_test.go proves key-private (keyprivate.go) on every host over
// synthetic entries: the rule over an lstat and an identity, and the
// check's wiring through the material member over a healthy tree whose key
// the probe reports variously. The probe of a build with ownership is
// proved over real files in keyprivate_unix_test.go; the fail-closed probe
// of every other build in keyprivate_other_test.go.

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

// mObserver is the identity the tests ask as: uid 1000, in groups 1000
// and 2000, root's owner of nothing.
var mObserver = storeIdentity{UID: 1000, Groups: []uint32{1000, 2000}}

// mRootKeyProbe is the probe materialRunWith injects: an lstat of the real
// path for existence and regularity, reported as root's, 0600, asked by
// mObserver.
func mRootKeyProbe(path string) (keyEntry, storeIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return keyEntry{}, mObserver, nil
	}
	return keyEntry{Exists: true, Regular: info.Mode().IsRegular(), UID: 0, GID: 0, Mode: 0o600}, mObserver, nil
}

// mKeyAs is a probe that reports every path as the given entry.
func mKeyAs(e keyEntry) keyProbe {
	return func(string) (keyEntry, storeIdentity, error) { return e, mObserver, nil }
}

func TestMaterialKeyPrivateRule(t *testing.T) {
	regular := func(uid, gid, mode uint32) keyEntry {
		return keyEntry{Exists: true, Regular: true, UID: uid, GID: gid, Mode: mode}
	}
	cases := []struct {
		name string
		e    keyEntry
		want string
	}{
		{"root 0600", regular(0, 0, 0o600), ""},
		{"root 0400", regular(0, 0, 0o400), ""},
		{"root:gt 0640, the deployment's", regular(0, 3000, 0o640), ""},
		{"root 0640 in a group the observer holds", regular(0, 2000, 0o640), "readable-by-observer"},
		{"root 0640 in the observer's primary group", regular(0, 1000, 0o640), "readable-by-observer"},
		{"owned by the observer, 0600", regular(1000, 3000, 0o600), "readable-by-observer"},
		{"owned by the observer, 0400", regular(1000, 3000, 0o400), "readable-by-observer"},
		{"root 0644", regular(0, 0, 0o644), "mode:0644"},
		{"root 0604", regular(0, 0, 0o604), "mode:0604"},
		{"root 0660", regular(0, 3000, 0o660), "mode:0660"},
		{"root 0650", regular(0, 3000, 0o650), "mode:0650"},
		{"root 0666", regular(0, 0, 0o666), "mode:0666"},
		{"root 0640 with the set-group-id bit", regular(0, 3000, 0o2640), "mode:2640"},
		{"root 0600 with the sticky bit", regular(0, 0, 0o1600), "mode:1600"},
		{"absent", keyEntry{}, "stat"},
		{"a directory", keyEntry{Exists: true, Regular: false, Mode: 0o755}, "not-regular"},
		{"a link", keyEntry{Exists: true, Regular: false, Mode: 0o777}, "not-regular"},
	}
	for _, c := range cases {
		if got := keyPrivateRule(c.e, mObserver); got != c.want {
			t.Errorf("%s: subject %q, want %q", c.name, got, c.want)
		}
	}
	// The mask names exactly the bits a key may not carry: everything but
	// owner read and write and group read.
	for _, bit := range []uint32{0o4000, 0o2000, 0o1000, 0o020, 0o010, 0o004, 0o002, 0o001} {
		if got := keyPrivateRule(regular(0, 0, 0o600|bit), mObserver); !strings.HasPrefix(got, "mode:") {
			t.Errorf("bit %04o: subject %q, want mode:", bit, got)
		}
	}
	for _, bit := range []uint32{0o400, 0o200, 0o040} {
		if got := keyPrivateRule(regular(0, 3000, bit), mObserver); got != "" {
			t.Errorf("bit %04o alone: subject %q, want none", bit, got)
		}
	}
}

func TestMaterialKeyPrivateSubject(t *testing.T) {
	if got := keyPrivateSubject("", mKeyAs(keyEntry{Exists: true, Regular: true, Mode: 0o600})); got != "no-path" {
		t.Errorf("no path: %q", got)
	}
	unsupported := func(string) (keyEntry, storeIdentity, error) {
		return keyEntry{}, storeIdentity{}, errKeyProbeUnsupported
	}
	if got := keyPrivateSubject("/k", unsupported); !strings.HasPrefix(got, "unsupported-os:") || got == "unsupported-os:" {
		t.Errorf("unsupported probe: %q", got)
	}
	failing := func(string) (keyEntry, storeIdentity, error) {
		return keyEntry{}, storeIdentity{}, errors.New("getgroups")
	}
	if got := keyPrivateSubject("/k", failing); got != "identity" {
		t.Errorf("identity unreadable: %q", got)
	}
	if got := keyPrivateSubject("/k", mKeyAs(keyEntry{Exists: true, Regular: true, Mode: 0o600})); got != "" {
		t.Errorf("private key: %q", got)
	}
}

// TestMaterialKeyPrivate is the check through the member: a healthy tree
// whose key the probe reports as private yields nothing; every other
// report is a finding with its subject; a material list without a key
// fails with none.
func TestMaterialKeyPrivate(t *testing.T) {
	f := mMaterial(t)
	root := materialTree(t, materialHealthy(f)...)
	run := func(e keyEntry) []Finding {
		return materialRunWith(t, root, MaterialChecks{KeyProbe: mKeyAs(e)})
	}
	regular := func(uid, gid, mode uint32) keyEntry {
		return keyEntry{Exists: true, Regular: true, UID: uid, GID: gid, Mode: mode}
	}
	materialWant(t, run(regular(0, 0, 0o600)))
	materialWant(t, run(regular(0, 3000, 0o640)))
	materialWant(t, run(regular(0, 0, 0o644)), Finding{"key-private", "mode:0644"})
	materialWant(t, run(regular(0, 2000, 0o640)), Finding{"key-private", "readable-by-observer"})
	materialWant(t, run(regular(1000, 3000, 0o600)), Finding{"key-private", "readable-by-observer"})
	materialWant(t, run(keyEntry{}), Finding{"key-private", "stat"})
	materialWant(t, run(keyEntry{Exists: true, Mode: 0o755}), Finding{"key-private", "not-regular"})
	// The probe cannot run: the check fails closed, once, and nothing
	// else changes.
	unsupported := func(string) (keyEntry, storeIdentity, error) {
		return keyEntry{}, storeIdentity{}, errKeyProbeUnsupported
	}
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: unsupported}), Finding{"key-private", "unsupported-os:" + runtime.GOOS})
	// The last word on the key is the reload's: the reload names a path
	// the probe reports absent while the start line's is private.
	lines := materialHealthy(f)
	lines[1] = strings.Replace(lines[1], jstr(f.key), jstr(f.key+".moved"), 1)
	probe := func(path string) (keyEntry, storeIdentity, error) {
		if path == f.key {
			return regular(0, 0, 0o600), mObserver, nil
		}
		return keyEntry{}, mObserver, nil
	}
	materialWant(t, materialRunWith(t, materialTree(t, lines...), MaterialChecks{KeyProbe: probe}), Finding{"material-loaded", "key"}, Finding{"key-private", "stat"})
	// A material list with no key at all cannot be shown private.
	entries := "[" + strings.Join([]string{entry("cert", f.cert, f.certSHA), entry("ca", f.ca, f.caSHA), entry("policy", f.policy, f.policySHA)}, ",") + "]"
	root = materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(entries, true, true, "applied", "")))
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: mKeyAs(regular(0, 0, 0o600))}), Finding{"key-private", "none"})
	// Every finding names the identifier once: two key entries, both
	// absent, are one finding with subject stat.
	entries = "[" + strings.Join([]string{entry("cert", f.cert, f.certSHA), entry("key", f.key, "null"), entry("key", f.key+".2", "null"), entry("ca", f.ca, f.caSHA), entry("policy", f.policy, f.policySHA)}, ",") + "]"
	root = materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(entries, true, true, "applied", "")))
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: mKeyAs(keyEntry{})}), Finding{"material-loaded", "key"}, Finding{"key-private", "stat"})
}
