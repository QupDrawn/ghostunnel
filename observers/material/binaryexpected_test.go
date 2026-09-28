package main

// binaryexpected_test.go proves binary-expected (materialchecks.go): the
// executable the start line names is still the file on disk and is the
// build the operator expects, over a stand-in executable written here.
// BenchmarkBinaryDigest measures what the check costs a cycle.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mBinaryBytes is the content of the stand-in executable every start line
// of this package's tests names unless it names another (mConfig).
const mBinaryBytes = "a stand-in for the proxy's executable\n"

// mBinarySHA is the SHA-256 of mBinaryBytes, the hash the healthy start
// lines record and the expectation materialRunWith gives by default.
var mBinarySHA = func() string {
	sum := sha256.Sum256([]byte(mBinaryBytes))
	return hex.EncodeToString(sum[:])
}()

// mBinaryPath is the stand-in executable TestMain writes for the test
// process and removes after it.
var mBinaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gt-material-binary-")
	if err != nil {
		panic(err)
	}
	mBinaryPath = filepath.Join(dir, "ghostunnel")
	if err := os.WriteFile(mBinaryPath, []byte(mBinaryBytes), 0o755); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// mBinaryEntry is a config.binary object for path and hash.
func mBinaryEntry(path, sha string) string {
	return `{"path":` + jstr(path) + `,"sha256":"` + sha + `"}`
}

// mBinaryTree is a healthy boot whose start line names the executable at
// path with hash sha.
func mBinaryTree(t *testing.T, f *mFiles, path, sha string) string {
	t.Helper()
	cfg := mConfigBinary(f.entries(), true, true, "applied", "", mBinaryEntry(path, sha))
	return materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, cfg))
}

// mStandIn writes a stand-in executable with the given bytes into a fresh
// directory and returns its path and hash.
func mStandIn(t *testing.T, content string) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ghostunnel")
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return p, hex.EncodeToString(sum[:])
}

func TestMaterialBinaryMatches(t *testing.T) {
	f := mMaterial(t)
	path, sha := mStandIn(t, "build one\n")
	materialWant(t, materialRunWith(t, mBinaryTree(t, f, path, sha), MaterialChecks{ExpectBinarySHA256: sha}))
}

func TestMaterialBinaryReplaced(t *testing.T) {
	f := mMaterial(t)
	path, sha := mStandIn(t, "build one\n")
	root := mBinaryTree(t, f, path, sha)
	checks := MaterialChecks{ExpectBinarySHA256: sha}
	materialWant(t, materialRunWith(t, root, checks))
	// The file is rewritten in place after the proxy started: its bytes
	// are no longer the ones the start line hashed.
	if err := os.WriteFile(path, []byte("build two\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, checks), Finding{"binary-expected", "changed"})
	// Replaced by rename with the same length and the same modification
	// time: still found, since the check reads the bytes.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(path), "ghostunnel.new")
	if err := os.WriteFile(other, []byte("build one!"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, checks), Finding{"binary-expected", "changed"})
	// Put back: the check passes again.
	if err := os.WriteFile(path, []byte("build one\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, checks))
}

func TestMaterialBinaryUnexpected(t *testing.T) {
	f := mMaterial(t)
	path, sha := mStandIn(t, "build one\n")
	root := mBinaryTree(t, f, path, sha)
	_, other := mStandIn(t, "build two\n")
	materialWant(t, materialRunWith(t, root, MaterialChecks{ExpectBinarySHA256: other}), Finding{"binary-expected", "unexpected"})
	// Replaced and unexpected at once: both subjects.
	if err := os.WriteFile(path, []byte("build three\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRunWith(t, root, MaterialChecks{ExpectBinarySHA256: other}), Finding{"binary-expected", "changed"}, Finding{"binary-expected", "unexpected"})
	// No expectation agrees with nothing. parseFlags refuses it; Run
	// judges it as it is given.
	root = mBinaryTree(t, f, mBinaryPath, mBinarySHA)
	live := procLiveness(blTable(t, 4242))
	got := materialSorted(MaterialChecks{Live: live, KeyProbe: mRootKeyProbe}.Run(&Config{TracesRoot: root, Now: mNow(t)}, &State{}, nil))
	materialWant(t, got, Finding{"binary-expected", "unexpected"})
}

func TestMaterialBinaryMissingOrUnreadable(t *testing.T) {
	f := mMaterial(t)
	path, sha := mStandIn(t, "build one\n")
	checks := MaterialChecks{ExpectBinarySHA256: sha}
	dir := filepath.Dir(path)
	// Missing.
	materialWant(t, materialRunWith(t, mBinaryTree(t, f, filepath.Join(dir, "absent"), sha), checks), Finding{"binary-expected", "changed"})
	// A directory at the path.
	materialWant(t, materialRunWith(t, mBinaryTree(t, f, dir, sha), checks), Finding{"binary-expected", "changed"})
	// A symbolic link at the path, even to the right bytes: the proxy
	// records the path with every link resolved, so a link at the path is a
	// replacement.
	link := filepath.Join(t.TempDir(), "ghostunnel")
	if err := os.Symlink(path, link); err == nil {
		materialWant(t, materialRunWith(t, mBinaryTree(t, f, link, sha), checks), Finding{"binary-expected", "changed"})
	} else {
		t.Logf("no symbolic link on this host (%v); the link case is not exercised", err)
	}
	// Unreadable: a mode that denies this user, where the mode binds it.
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		locked, lockedSHA := mStandIn(t, "build one\n")
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
		materialWant(t, materialRunWith(t, mBinaryTree(t, f, locked, lockedSHA), MaterialChecks{ExpectBinarySHA256: lockedSHA}), Finding{"binary-expected", "changed"})
	}
}

func TestMaterialBinaryBound(t *testing.T) {
	// A sparse file one byte above the bound is refused unread.
	p := filepath.Join(t.TempDir(), "ghostunnel")
	fh, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(maxBinaryBytes + 1); err != nil {
		fh.Close()
		t.Fatal(err)
	}
	fh.Close()
	if _, err := binaryDigest(p); err == nil || !strings.Contains(err.Error(), "exceeds the bound") {
		t.Fatalf("a file above the bound: %v", err)
	}
	if got, want := maxBinaryBytes, 512<<20; got != want {
		t.Fatalf("bound %d, want %d", got, want)
	}
	if got, err := binaryDigest(mBinaryPath); err != nil || got != mBinarySHA {
		t.Fatalf("the stand-in hashes to %q, %v; want %q", got, err, mBinarySHA)
	}
}

func TestMaterialExpectBinaryFlag(t *testing.T) {
	base := []string{"-heartbeat-max-age", "30s", "-slot-owners", "tunnel=a,admin=b,material=c,super=d"}
	good := strings.Repeat("0123456789abcdef", 4)
	cfg, _, _, err := parseFlags(append(base, "-expect-binary-sha256", good))
	if err != nil {
		t.Fatalf("a well-formed expectation refused: %v", err)
	}
	if got := cfg.Local.(MaterialChecks).ExpectBinarySHA256; got != good {
		t.Fatalf("expectation carried as %q", got)
	}
	for name, args := range map[string][]string{
		"absent":      base,
		"empty":       append(append([]string{}, base...), "-expect-binary-sha256="),
		"short":       append(append([]string{}, base...), "-expect-binary-sha256", good[:63]),
		"long":        append(append([]string{}, base...), "-expect-binary-sha256", good+"0"),
		"upper-case":  append(append([]string{}, base...), "-expect-binary-sha256", strings.ToUpper(good)),
		"not hex":     append(append([]string{}, base...), "-expect-binary-sha256", "g"+good[1:]),
		"spaced":      append(append([]string{}, base...), "-expect-binary-sha256", " "+good[1:]),
		"sha256 form": append(append([]string{}, base...), "-expect-binary-sha256", "sha256:"+good),
	} {
		if _, _, _, err := parseFlags(args); err == nil {
			t.Errorf("%s: -expect-binary-sha256 accepted", name)
		}
	}
}

// BenchmarkBinaryDigest is binary-expected's cost per cycle: one full
// hash of the executable. GT_BENCH_BINARY names the file (a ghostunnel
// build); the test binary stands in when it is unset.
func BenchmarkBinaryDigest(b *testing.B) {
	path := os.Getenv("GT_BENCH_BINARY")
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			b.Fatal(err)
		}
		path = exe
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(info.Size())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := binaryDigest(path); err != nil {
			b.Fatal(err)
		}
	}
}
