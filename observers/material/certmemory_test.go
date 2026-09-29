package main

// certmemory_test.go proves material-loaded's memory of certificate parses
// (materialchecks.go, contentmemo.go): the file is read and hashed every
// cycle, parsed once per content, and its validity windows judged against
// the clock every cycle.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaterialRemembersCertificateParsesByContent(t *testing.T) {
	pem, err := os.ReadFile(filepath.Join("..", "testdata", "pki", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pem)
	hash := hex.EncodeToString(sum[:])
	m := gtMaterial{Material: "ca", Path: path, SHA256: &hash}
	inside := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2037, 1, 1, 0, 0, 0, 0, time.UTC)

	prev := parseCertificates
	t.Cleanup(func() { parseCertificates = prev })
	parses := 0
	parseCertificates = func(b []byte) certificateParse { parses++; return prev(b) }

	certs := &contentMemo[certificateParse]{}
	look := func(now time.Time) bool {
		certs.begin()
		defer certs.end()
		return materialOnDisk(m, now, certs)
	}
	if first, second := look(inside), look(inside); !first || !second || parses != 1 {
		t.Fatalf("an unchanged bundle inside its window: %d parses, want 1", parses)
	}
	// The clock is judged every cycle: remembered, and out of its window.
	if look(after) || parses != 1 {
		t.Fatalf("the remembered bundle past its window passed, or was parsed again (%d)", parses)
	}
	if look(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("the remembered bundle before its window passed")
	}
	// Other bytes under the same path: hashed, found not to be the loaded
	// hash, never judged from the memory.
	if err := os.WriteFile(path, append(append([]byte{}, pem...), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if look(inside) {
		t.Fatal("a bundle that no longer hashes as loaded passed")
	}
	// Bytes that are not a certificate, loaded under their own hash: parsed,
	// and remembered as not valid.
	junk := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(path, junk, 0o644); err != nil {
		t.Fatal(err)
	}
	js := sha256.Sum256(junk)
	jh := hex.EncodeToString(js[:])
	m.SHA256 = &jh
	parses = 0
	if first, second := look(inside), look(inside); first || second || parses != 1 {
		t.Fatalf("a bundle that does not parse passed, or was parsed %d times", parses)
	}
	if len(certs.entries) != 1 {
		t.Fatalf("%d parses remembered, want the one content asked for last", len(certs.entries))
	}
	// Back to the bundle, in the very next cycle: judged as the bundle.
	if err := os.WriteFile(path, pem, 0o644); err != nil {
		t.Fatal(err)
	}
	m.SHA256 = &hash
	if !look(inside) || parses != 2 {
		t.Fatalf("the bundle after the junk: parses %d, want 2 and valid", parses)
	}
	// No memory: the same answers, a parse every time.
	parses = 0
	if first, second := materialOnDisk(m, inside, nil), materialOnDisk(m, inside, nil); !first || !second || parses != 2 {
		t.Fatalf("without a memory: %d parses, want 2", parses)
	}
}

// TestCertificatesValidOverTheTestPKI: certificatesValid is the parse and
// the clock together: at least one certificate, every one parsed, now
// inside every window.
func TestCertificatesValidOverTheTestPKI(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for name, want := range map[string]bool{"ca.pem": true, "leaf-client.pem": true, "leaf-expired.pem": false} {
		b, err := os.ReadFile(filepath.Join("..", "testdata", "pki", name))
		if err != nil {
			t.Fatal(err)
		}
		if got := certificatesValid(b, now); got != want {
			t.Errorf("%s: valid %v, want %v", name, got, want)
		}
		both := append(append([]byte{}, b...), mustRead(t, "ca.pem")...)
		if got := certificatesValid(both, now); got != want {
			t.Errorf("%s then ca.pem: valid %v, want %v", name, got, want)
		}
	}
	if certificatesValid([]byte("no pem here"), now) {
		t.Error("bytes with no certificate are valid")
	}
	// One block that does not parse makes the whole file invalid, beside
	// good ones, before them or after.
	junk := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	ca := mustRead(t, "ca.pem")
	for _, b := range [][]byte{append(append([]byte{}, ca...), junk...), append(append([]byte{}, junk...), ca...)} {
		if certificatesValid(b, now) {
			t.Error("a bundle holding a block that does not parse is valid")
		}
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "pki", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Through the member's cycle: the memory lives in the member's State, holds
// the parse of each certificate and bundle the boot loaded, and forgets
// every content the cycle did not ask for.
func TestMaterialCertificateMemoryIsBoundedByTheCycle(t *testing.T) {
	root := materialTree(t, materialHealthy(mMaterial(t))...)
	checks := MaterialChecks{Live: procLiveness(blTable(t, 4242)), ExpectBinarySHA256: mBinarySHA, KeyProbe: mRootKeyProbe}
	st := &State{}
	cfg := &Config{TracesRoot: root, Now: mNow(t)}
	first := materialSorted(checks.Run(cfg, st, nil))
	if st.Certificates == nil || len(st.Certificates.entries) == 0 {
		t.Fatal("the cycle kept no certificate parse")
	}
	kept := len(st.Certificates.entries)
	st.Certificates.entries["stale"] = &contentEntry[certificateParse]{v: certificateParse{ok: true}}
	prev := parseCertificates
	t.Cleanup(func() { parseCertificates = prev })
	parses := 0
	parseCertificates = func(b []byte) certificateParse { parses++; return prev(b) }
	second := materialSorted(checks.Run(cfg, st, nil))
	if parses != 0 {
		t.Fatalf("an unchanged boot's material was parsed %d times", parses)
	}
	if _, ok := st.Certificates.entries["stale"]; ok || len(st.Certificates.entries) != kept {
		t.Fatalf("the memory holds %d parses after the cycle, want the %d it asked for", len(st.Certificates.entries), kept)
	}
	if len(first) != len(second) {
		t.Fatalf("the cycle with the memory found %v, without %v", second, first)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("the cycle with the memory found %v, without %v", second, first)
		}
	}
}
