//go:build unix

package main

// keyprivate_unix_test.go proves the key probe of a build with POSIX
// ownership over real files: a key the test writes and chmods is judged as
// the deployment's would be. The test's own identity owns every file it
// writes, so the rule is asked twice: as a member that owns nothing and is
// in no group (mStranger, composed with the real lstat), which is the
// deployment's case, and as the process itself, for which every file it
// owns is readable-by-observer whatever its mode.

import (
	"os"
	"path/filepath"
	"testing"
)

// mStranger is an identity that owns nothing on this host and holds no
// group: uid 4294967294, which no account is given.
var mStranger = storeIdentity{UID: 0xFFFFFFFE}

// asObserver is the real lstat with mStranger asking.
func asObserver(path string) (keyEntry, storeIdentity, error) {
	e, _, err := platformKeyProbe(path)
	return e, mStranger, err
}

func TestMaterialKeyPrivateOnDisk(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(key, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The probe reports the file as it is.
	e, who, err := platformKeyProbe(key)
	if err != nil || !e.Exists || !e.Regular || e.UID != uint32(os.Getuid()) || e.GID != uint32(os.Getgid()) {
		t.Fatalf("probe of a 0600 file: %+v %v (uid %d gid %d)", e, err, os.Getuid(), os.Getgid())
	}
	if who.UID != uint32(os.Getuid()) || !groupHeld(uint32(os.Getgid()), who.Groups) {
		t.Fatalf("identity %+v is not this process's", who)
	}
	for _, c := range []struct {
		mode os.FileMode
		want string
	}{
		{0o600, ""},
		{0o400, ""},
		{0o640, ""},
		{0o644, "mode:0644"},
		{0o604, "mode:0604"},
		{0o660, "mode:0660"},
		{0o664, "mode:0664"},
		{0o666, "mode:0666"},
	} {
		if err := os.Chmod(key, c.mode); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Lstat(key); err != nil || info.Mode().Perm() != c.mode {
			t.Skipf("this filesystem does not hold a mode of %04o (has %v)", c.mode, info.Mode().Perm())
		}
		if got := keyPrivateSubject(key, asObserver); got != c.want {
			t.Errorf("mode %04o as a member owning nothing: subject %q, want %q", c.mode, got, c.want)
		}
		// This process owns the file: readable by it at every mode, and the
		// mode's own finding first where there is one.
		want := c.want
		if want == "" {
			want = "readable-by-observer"
		}
		if got := keyPrivateSubject(key, platformKeyProbe); got != want {
			t.Errorf("mode %04o as the owner: subject %q, want %q", c.mode, got, want)
		}
	}
	// Through the member, over the real probe: 0600 passes, 0644 fails
	// with the mode, and a path that is not there fails with stat.
	f := mMaterial(t)
	root := materialTree(t, materialHealthy(f)...)
	if err := os.Chmod(f.key, 0o600); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: asObserver}))
	if err := os.Chmod(f.key, 0o644); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: asObserver}), Finding{"key-private", "mode:0644"})
	if err := os.Remove(f.key); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: asObserver}), Finding{"material-loaded", "key"}, Finding{"key-private", "stat"})
	// A symbolic link to a private file is judged as the link.
	target := filepath.Join(dir, "real.pem")
	if err := os.WriteFile(target, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, f.key); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: asObserver}), Finding{"key-private", "not-regular"})
	// A directory is not a key.
	if err := os.Remove(f.key); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.key, 0o700); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, MaterialChecks{KeyProbe: asObserver}), Finding{"material-loaded", "key"}, Finding{"key-private", "not-regular"})
}
