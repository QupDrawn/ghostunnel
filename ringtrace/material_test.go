package ringtrace

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWriteMaterialWritesOnce: the first write of a material file lands
// material/<sha256>, no suffix, whose content is the bytes given and whose
// name is their SHA-256, through a synced .tmp, a rename and a directory
// sync; a second write of the same bytes syncs nothing and changes
// nothing; distinct bytes are distinct files; no .tmp is left behind.
func TestWriteMaterialWritesOnce(t *testing.T) {
	root := t.TempDir()
	bundle := []byte("-----BEGIN CERTIFICATE-----\nnot really\n-----END CERTIFICATE-----\n")
	rec := &chainSyncRecorder{}
	SetChainSyncHook(rec.hook)
	defer SetChainSyncHook(nil)

	hash, err := WriteMaterial(root, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if hash != MaterialHash(bundle) || len(hash) != 64 {
		t.Fatalf("hash %q is not the SHA-256 of the content", hash)
	}
	path := MaterialPath(root, hash)
	if path != filepath.Join(root, "material", hash) {
		t.Fatalf("MaterialPath = %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bundle) {
		t.Fatal("the file's content is not the bytes given")
	}
	want := []string{root, filepath.Join(root, "material", hash+".tmp"), filepath.Join(root, "material")}
	if strings.Join(rec.paths, "|") != strings.Join(want, "|") {
		t.Fatalf("syncs = %v, want %v", rec.paths, want)
	}
	entries, err := os.ReadDir(filepath.Join(root, "material"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != hash {
		t.Fatalf("material/ holds %v, want only %s", entries, hash)
	}
	info1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	again, err := WriteMaterial(root, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if again != hash {
		t.Fatalf("second write named %s, want %s", again, hash)
	}
	if rec.count() != len(want) {
		t.Fatalf("the second write synced: %v", rec.paths[len(want):])
	}
	info2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info1.ModTime().Equal(info2.ModTime()) || info1.Size() != info2.Size() {
		t.Fatal("the second write touched the file")
	}
	if mode := info2.Mode().Perm(); runtime.GOOS != "windows" && mode != 0o644 {
		t.Fatalf("file mode %o, want 0644", mode)
	}

	other, err := WriteMaterial(root, append([]byte{}, bundle[:len(bundle)-1]...))
	if err != nil {
		t.Fatal(err)
	}
	if other == hash {
		t.Fatal("different bytes got the same name")
	}
	entries, _ = os.ReadDir(filepath.Join(root, "material"))
	if len(entries) != 2 {
		t.Fatalf("material/ holds %d entries, want 2", len(entries))
	}
	// The chain store is untouched by the material store.
	if _, err := os.Stat(filepath.Join(root, "chains")); !os.IsNotExist(err) {
		t.Fatalf("chains/ appeared: %v", err)
	}
}

// TestWriteMaterialRefuses: empty content is no material; content over the
// bound is refused; a material entry that is not a directory fails the
// write.
func TestWriteMaterialRefuses(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteMaterial(root, nil); err == nil {
		t.Fatal("empty material must be refused")
	}
	if _, err := WriteMaterial(root, make([]byte, MaxMaterialBytes+1)); err != ErrMaterialTooLong {
		t.Fatalf("oversize material must be refused with ErrMaterialTooLong, got %v", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("a refused write created %v", entries)
	}
	if err := os.WriteFile(filepath.Join(root, "material"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteMaterial(root, []byte("x")); err == nil {
		t.Fatal("a regular file at material must fail the write")
	} else if !strings.HasPrefix(err.Error(), "ringtrace: material: ") {
		t.Fatalf("error %q is not the material store's", err)
	}
}

// TestReadMaterialFailsClosed: ReadMaterial returns the bytes under the
// name and nothing on a tampered byte, a wrong name, a missing file, a
// .tmp left behind, a symbolic link where the platform allows one, a name
// that is not a hash, a directory at the name, a file over the bound and a
// root with no store.
func TestReadMaterialFailsClosed(t *testing.T) {
	root := t.TempDir()
	bundle := []byte("-----BEGIN CERTIFICATE-----\nbundle\n-----END CERTIFICATE-----\n")
	hash, err := WriteMaterial(root, bundle)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadMaterial(root, hash)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bundle) {
		t.Fatal("the bytes read are not the bytes written")
	}
	dir := filepath.Join(root, "material")
	refused := func(name, hash string) {
		t.Helper()
		data, err := ReadMaterial(root, hash)
		if err == nil {
			t.Fatalf("%s: read but must be refused", name)
		}
		if data != nil {
			t.Fatalf("%s: returned something with the error", name)
		}
	}

	tampered := append([]byte{}, bundle...)
	tampered[10] ^= 0x01
	if err := os.WriteFile(MaterialPath(root, hash), tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	refused("tampered byte", hash)
	if err := os.WriteFile(MaterialPath(root, hash), bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMaterial(root, hash); err != nil {
		t.Fatalf("restored: %v", err)
	}

	wrong := strings.Repeat("0", 64)
	if err := os.WriteFile(MaterialPath(root, wrong), bundle, 0o644); err != nil {
		t.Fatal(err)
	}
	refused("wrong name", wrong)

	refused("missing", strings.Repeat("1", 64))

	tmpHash := MaterialHash([]byte("pending"))
	if err := os.WriteFile(filepath.Join(dir, tmpHash+".tmp"), []byte("pending"), 0o644); err != nil {
		t.Fatal(err)
	}
	refused(".tmp only", tmpHash)

	if err := os.Symlink(MaterialPath(root, hash), MaterialPath(root, strings.Repeat("2", 64))); err == nil {
		refused("symbolic link", strings.Repeat("2", 64))
	} else {
		t.Logf("no symbolic links here (%v); that case is not run", err)
	}

	for _, bad := range []string{strings.ToUpper(hash), hash[:63], "../" + hash, "", hash + ".tmp", hash + ".der"} {
		refused("name "+bad, bad)
	}

	if err := os.Mkdir(MaterialPath(root, strings.Repeat("3", 64)), 0o755); err != nil {
		t.Fatal(err)
	}
	refused("directory", strings.Repeat("3", 64))

	big := make([]byte, MaxMaterialBytes+1)
	copy(big, bundle)
	if err := os.WriteFile(MaterialPath(root, MaterialHash(big)), big, 0o644); err != nil {
		t.Fatal(err)
	}
	refused("over the bound", MaterialHash(big))

	if _, err := ReadMaterial(t.TempDir(), hash); err == nil {
		t.Fatal("a root with no material/ must be refused")
	}
	// The chain store does not answer for the material store: the same
	// bytes under chains/ are not material.
	if _, err := WriteChain(root, bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(MaterialPath(root, hash)); err != nil {
		t.Fatal(err)
	}
	refused("in the chain store only", hash)
}

// TestMaterialDirIsAdmittedBesideTheBoots: the reader and the emitter
// accept gt/material/ beside the boots, the lock and gt/chains/, do not
// walk it, and refuse a regular file at that name.
func TestMaterialDirIsAdmittedBesideTheBoots(t *testing.T) {
	root := t.TempDir()
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 2)})
	if err := os.WriteFile(filepath.Join(root, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteMaterial(root, []byte("bundle")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "material", "stray.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("material/ beside the boots is the tree: %v", err)
	}
	if len(tr.Boots) != 1 {
		t.Fatalf("want 1 boot, got %d", len(tr.Boots))
	}
	if boots, err := listBoots(root); err != nil || len(boots) != 1 {
		t.Fatalf("listBoots = %v, %v", boots, err)
	}
	if err := os.RemoveAll(filepath.Join(root, "material")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "material"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "a regular file named material")
	if _, err := listBoots(root); err == nil {
		t.Fatal("the emitter must refuse a regular file named material")
	}
}

// TestStoreMaterialHoldsTheBytesToTheEntry: StoreMaterial stores nothing
// for a list with no hashed ca entry and does not consult the bytes;
// refuses a hashed ca entry with no bytes, and bytes that hash to
// something other than the entry, with nothing written; and stores the
// bytes as hashed under the entry's hash.
func TestStoreMaterialHoldsTheBytesToTheEntry(t *testing.T) {
	root := t.TempDir()
	bundle := []byte("-----BEGIN CERTIFICATE-----\nbundle\n-----END CERTIFICATE-----\n")
	hash := MaterialHash(bundle)
	other := strings.Repeat("0", 64)
	nothingStored := func(what string) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(root, "material")); !os.IsNotExist(err) {
			t.Fatalf("%s: material/ appeared (%v)", what, err)
		}
	}
	if err := StoreMaterial(root, []Material{{Material: "cert", Path: "/c", SHA256: &hash}, {Material: "ca", Path: ""}}, nil); err != nil {
		t.Fatalf("no hashed ca entry: %v", err)
	}
	nothingStored("no hashed ca entry")
	if err := StoreMaterial(root, []Material{{Material: "ca", Path: "/ca.pem", SHA256: &hash}}, nil); err == nil {
		t.Fatal("a hashed ca entry with no bytes must be refused")
	}
	nothingStored("hashed entry, no bytes")
	if err := StoreMaterial(root, []Material{{Material: "ca", Path: "/ca.pem", SHA256: &other}}, bundle); err == nil {
		t.Fatal("bytes that do not hash to the entry must be refused")
	}
	nothingStored("bytes of another hash")
	if err := StoreMaterial(root, []Material{{Material: "cert", Path: "/c", SHA256: &other}, {Material: "ca", Path: "/ca.pem", SHA256: &hash}}, bundle); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMaterial(root, hash)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bundle) {
		t.Fatal("the bytes stored are not the bytes given")
	}
}

// TestOpenStoresTheCABundleBeforeTheStartLine: Open with a configuration
// that hashes a CA bundle stores the bundle's bytes under gt/material/
// under the hash the start line names, before any boot is created: bytes
// that do not hash to the entry, or a regular file where material/ must
// be, fail Open with no boot directory; the bundle given lands under its
// hash and the start line names it.
func TestOpenStoresTheCABundleBeforeTheStartLine(t *testing.T) {
	root := t.TempDir()
	bundle := []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")
	hash := MaterialHash(bundle)
	cfg := testConfig()
	cfg.Material = append(cfg.Material, Material{Material: "ca", Path: "/etc/gt/ca.pem", SHA256: &hash})
	names := func() []string {
		t.Helper()
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}

	if _, err := Open(root, Options{Config: cfg, Now: fixedClock(), CABundle: []byte("not the bundle")}); err == nil {
		t.Fatal("bytes that do not hash to the ca entry must fail Open")
	}
	if got := strings.Join(names(), " "); got != "lock" {
		t.Fatalf("a refused Open left %q under the root, want only the lock", got)
	}
	if _, err := Open(root, Options{Config: cfg, Now: fixedClock()}); err == nil {
		t.Fatal("a hashed ca entry with no bundle must fail Open")
	}
	if got := strings.Join(names(), " "); got != "lock" {
		t.Fatalf("a refused Open left %q under the root, want only the lock", got)
	}
	if err := os.WriteFile(filepath.Join(root, "material"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, Options{Config: cfg, Now: fixedClock(), CABundle: bundle}); err == nil {
		t.Fatal("a regular file where material/ must be must fail Open")
	}
	if got := strings.Join(names(), " "); got != "lock material" {
		t.Fatalf("a refused Open left %q under the root, want the lock and the stray file", got)
	}
	if err := os.Remove(filepath.Join(root, "material")); err != nil {
		t.Fatal(err)
	}

	e, err := Open(root, Options{Config: cfg, Now: fixedClock(), CABundle: bundle})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	got, err := ReadMaterial(root, hash)
	if err != nil {
		t.Fatalf("the bundle is not in the store under the start line's hash: %v", err)
	}
	if string(got) != string(bundle) {
		t.Fatal("the bytes stored are not the bundle")
	}
	if got := strings.Join(names(), " "); got != "0000000001 lock material" {
		t.Fatalf("root holds %q, want the boot, the lock and the store", got)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	start, ok := tr.Boots[0].Records[0].Body.(*Start)
	if !ok {
		t.Fatalf("line 1 is %T", tr.Boots[0].Records[0].Body)
	}
	var recorded *string
	for _, m := range start.Config.Material {
		if m.Material == "ca" {
			recorded = m.SHA256
		}
	}
	if recorded == nil || *recorded != hash {
		t.Fatalf("the start line records ca %v, want %s", recorded, hash)
	}
}
