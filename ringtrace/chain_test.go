package ringtrace

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testChain issues a CA and a leaf it signs and returns their DER, leaf
// first, as a client presents them.
func testChain(t *testing.T) (leaf, ca []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "chain-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	ca, err = x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(ca)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "chain-test-leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leaf, err = x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, ca
}

// chainSyncRecorder records every sync the chain store makes, passing each
// through to the platform.
type chainSyncRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (r *chainSyncRecorder) hook(path string, f *os.File) error {
	r.mu.Lock()
	r.paths = append(r.paths, path)
	r.mu.Unlock()
	if f == nil {
		return nil
	}
	return f.Sync()
}

func (r *chainSyncRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

// TestWriteChainWritesOnce: the first write of a chain lands
// chains/<sha256>.der whose content is the bytes given and whose name is
// their SHA-256, through a synced .tmp, a rename and a directory sync; a
// second write of the same bytes syncs nothing and changes nothing; no
// .tmp is left behind.
func TestWriteChainWritesOnce(t *testing.T) {
	withUmask022(t)
	root := t.TempDir()
	leaf, ca := testChain(t)
	der := append(append([]byte{}, leaf...), ca...)
	rec := &chainSyncRecorder{}
	SetChainSyncHook(rec.hook)
	defer SetChainSyncHook(nil)

	hash, err := WriteChain(root, der)
	if err != nil {
		t.Fatal(err)
	}
	if hash != ChainHash(der) || len(hash) != 64 {
		t.Fatalf("hash %q is not the SHA-256 of the content", hash)
	}
	path := ChainPath(root, hash)
	if path != filepath.Join(root, "chains", hash+".der") {
		t.Fatalf("ChainPath = %s", path)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(der) {
		t.Fatal("the file's content is not the bytes given")
	}
	// The first write: the root synced for the new directory, the .tmp
	// synced, the directory synced after the rename.
	want := []string{root, filepath.Join(root, "chains", hash+".tmp"), filepath.Join(root, "chains")}
	if strings.Join(rec.paths, "|") != strings.Join(want, "|") {
		t.Fatalf("syncs = %v, want %v", rec.paths, want)
	}
	entries, err := os.ReadDir(filepath.Join(root, "chains"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != hash+".der" {
		t.Fatalf("chains/ holds %d entries, want only %s.der", len(entries), hash)
	}
	info1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	again, err := WriteChain(root, der)
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
	// The store is readable by the owner and the group alone: the chains
	// directory is requested 0750 and a chain file 0640, the emitter's
	// DirMode and FileMode, and under a umask of 022 that is exactly what
	// lands (assertMode, emitter_test.go). The values are spelled here, not
	// taken from the constants, so a constant that drifts fails this test
	// too; where the platform reports modes, what landed is checked as well.
	if DirMode != 0o750 || FileMode != 0o640 {
		t.Fatalf("DirMode %04o, FileMode %04o; want 0750 and 0640", DirMode, FileMode)
	}
	assertMode(t, filepath.Join(root, "chains"), 0o750)
	assertMode(t, path, 0o640)

	// Two distinct chains are two files.
	other, err := WriteChain(root, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if other == hash {
		t.Fatal("a different chain got the same name")
	}
	entries, _ = os.ReadDir(filepath.Join(root, "chains"))
	if len(entries) != 2 {
		t.Fatalf("chains/ holds %d entries, want 2", len(entries))
	}
}

// TestWriteChainRefuses: nothing presented is no chain; a chain over the
// bound is refused; a chains entry that is not a directory fails the write.
func TestWriteChainRefuses(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteChain(root, nil); err == nil {
		t.Fatal("an empty chain must be refused")
	}
	if _, err := WriteChain(root, make([]byte, MaxChainBytes+1)); err != ErrChainTooLong {
		t.Fatalf("an oversize chain must be refused with ErrChainTooLong, got %v", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("a refused write created %v", entries)
	}
	if err := os.WriteFile(filepath.Join(root, "chains"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	leaf, _ := testChain(t)
	if _, err := WriteChain(root, leaf); err == nil {
		t.Fatal("a regular file at chains must fail the write")
	}
}

// TestWriteChainConcurrent: many goroutines writing the same first-seen
// chain at once leave one file with the right content and no .tmp.
func TestWriteChainConcurrent(t *testing.T) {
	root := t.TempDir()
	leaf, ca := testChain(t)
	der := append(append([]byte{}, leaf...), ca...)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := WriteChain(root, der); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "chains"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != ChainHash(der)+".der" {
		t.Fatalf("chains/ holds %v", entries)
	}
	certs, got, err := ReadChain(root, ChainHash(der))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || string(got) != string(der) {
		t.Fatal("the file is not the chain")
	}
}

// TestReadChainInOrder: ReadChain returns the certificates in presented
// order, leaf first, and the bytes it read.
func TestReadChainInOrder(t *testing.T) {
	root := t.TempDir()
	leaf, ca := testChain(t)
	der := append(append([]byte{}, leaf...), ca...)
	hash, err := WriteChain(root, der)
	if err != nil {
		t.Fatal(err)
	}
	certs, got, err := ReadChain(root, hash)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(der) {
		t.Fatal("bytes differ")
	}
	if len(certs) != 2 {
		t.Fatalf("want 2 certificates, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "chain-test-leaf" || certs[1].Subject.CommonName != "chain-test-ca" {
		t.Fatalf("order: %s, %s", certs[0].Subject.CommonName, certs[1].Subject.CommonName)
	}
	if string(certs[0].Raw) != string(leaf) || string(certs[1].Raw) != string(ca) {
		t.Fatal("the certificates are not the DER written")
	}
	// The reversed order is a different chain with a different name.
	reversed, err := WriteChain(root, append(append([]byte{}, ca...), leaf...))
	if err != nil {
		t.Fatal(err)
	}
	if reversed == hash {
		t.Fatal("presented order is part of the identity")
	}
}

// TestReadChainFailsClosed: a tampered byte, a file under a name that is
// not its hash, a missing file, a .tmp left behind (never read), a
// symbolic link, a name that is not a hash, content that hashes to its
// name but is not DER, and a file over the bound are each refused with
// nothing returned.
func TestReadChainFailsClosed(t *testing.T) {
	root := t.TempDir()
	leaf, ca := testChain(t)
	der := append(append([]byte{}, leaf...), ca...)
	hash, err := WriteChain(root, der)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "chains")
	refused := func(name, hash string) {
		t.Helper()
		certs, data, err := ReadChain(root, hash)
		if err == nil {
			t.Fatalf("%s: read but must be refused", name)
		}
		if certs != nil || data != nil {
			t.Fatalf("%s: returned something with the error", name)
		}
	}

	// Tampered: one byte flipped inside the leaf's signature.
	tampered := append([]byte{}, der...)
	tampered[len(leaf)-1] ^= 0x01
	if err := os.WriteFile(ChainPath(root, hash), tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	refused("tampered byte", hash)
	if err := os.WriteFile(ChainPath(root, hash), der, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadChain(root, hash); err != nil {
		t.Fatalf("restored: %v", err)
	}

	// Wrong name: the right content under another hash's name.
	wrong := strings.Repeat("0", 64)
	if err := os.WriteFile(ChainPath(root, wrong), der, 0o644); err != nil {
		t.Fatal(err)
	}
	refused("wrong name", wrong)

	// Missing.
	refused("missing", strings.Repeat("1", 64))

	// A .tmp left behind is never read, whatever it holds.
	tmpHash := ChainHash(leaf)
	if err := os.WriteFile(filepath.Join(dir, tmpHash+".tmp"), leaf, 0o644); err != nil {
		t.Fatal(err)
	}
	refused(".tmp only", tmpHash)

	// A symbolic link is judged as the link.
	if err := os.Symlink(ChainPath(root, hash), filepath.Join(dir, strings.Repeat("2", 64)+".der")); err == nil {
		refused("symbolic link", strings.Repeat("2", 64))
	} else {
		t.Logf("no symbolic links here (%v); that case is not run", err)
	}

	// Not a hash: upper case, short, a path.
	for _, bad := range []string{strings.ToUpper(hash), hash[:63], "../" + hash, "", hash + ".der"} {
		refused("name "+bad, bad)
	}

	// Content that hashes to its name but is not DER.
	junk := []byte("not a certificate")
	if err := os.WriteFile(ChainPath(root, ChainHash(junk)), junk, 0o644); err != nil {
		t.Fatal(err)
	}
	refused("not DER", ChainHash(junk))

	// A directory at the name.
	if err := os.Mkdir(ChainPath(root, strings.Repeat("3", 64)), 0o755); err != nil {
		t.Fatal(err)
	}
	refused("directory", strings.Repeat("3", 64))

	// Over the bound, named by its hash.
	big := make([]byte, MaxChainBytes+1)
	copy(big, der)
	if err := os.WriteFile(ChainPath(root, ChainHash(big)), big, 0o644); err != nil {
		t.Fatal(err)
	}
	refused("over the bound", ChainHash(big))

	// The store's directory absent.
	if _, _, err := ReadChain(t.TempDir(), hash); err == nil {
		t.Fatal("a root with no chains/ must be refused")
	}
}

// TestChainsDirIsTheOneOtherEntry: the reader and the emitter accept
// gt/chains/ beside the boot directories and the lock, and still refuse
// any other stray entry, or chains as a regular file.
func TestChainsDirIsTheOneOtherEntry(t *testing.T) {
	root := t.TempDir()
	writeBoot(t, root, 1, map[string][]Record{"0000000001.trace": bootRecords(1, 2)})
	if err := os.WriteFile(filepath.Join(root, "lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "chains"), 0o755); err != nil {
		t.Fatal(err)
	}
	leaf, _ := testChain(t)
	if _, err := WriteChain(root, leaf); err != nil {
		t.Fatal(err)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("chains/ beside the boots is the tree: %v", err)
	}
	if len(tr.Boots) != 1 {
		t.Fatalf("want 1 boot, got %d", len(tr.Boots))
	}
	boots, err := listBoots(root)
	if err != nil || len(boots) != 1 {
		t.Fatalf("listBoots = %v, %v", boots, err)
	}

	if err := os.Mkdir(filepath.Join(root, "chain"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "a directory that is not chains")
	if err := os.Remove(filepath.Join(root, "chain")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "chains.tmp"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "a file beside chains")
	if err := os.Remove(filepath.Join(root, "chains.tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "chains")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "chains"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	expectMalformed(t, root, "a regular file named chains")
	if _, err := listBoots(root); err == nil {
		t.Fatal("the emitter must refuse a regular file named chains")
	}
}
