package main

// localchecks_test.go proves the material member's surface checks against
// synthetic gt/ trees written by hand in the exact ringtrace format and
// real files on disk: a certificate made here, its key, a CA bundle and a
// policy. One healthy tree yields nothing; one tree per violation yields
// exactly the expected finding; the unreadable trees yield a finding for
// every check because no check could run.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const materialNow = "2026-09-24T12:00:00Z"

func mNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, materialNow)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

// mFiles is the trust material on disk for one test.
type mFiles struct {
	dir                       string
	cert, key, ca, policy     string
	certSHA, caSHA, policySHA string
}

// mWriteCert writes a self-signed certificate valid over [from, to] and its
// key, and returns the PEM of the certificate.
func mWriteCert(t *testing.T, certPath, keyPath string, from, to time.Time) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ghostunnel-test"},
		NotBefore:             from,
		NotAfter:              to,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPEM
}

func mSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// mMaterial writes a healthy set of files valid around materialNow.
func mMaterial(t *testing.T) *mFiles {
	t.Helper()
	now := mNow(t)
	f := &mFiles{dir: t.TempDir()}
	f.cert = filepath.Join(f.dir, "cert.pem")
	f.key = filepath.Join(f.dir, "key.pem")
	f.ca = filepath.Join(f.dir, "ca.pem")
	f.policy = filepath.Join(f.dir, "policy.rego")
	mWriteCert(t, f.cert, f.key, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	caPEM := mWriteCert(t, f.ca, filepath.Join(f.dir, "ca-key.pem"), now.Add(-48*time.Hour), now.Add(48*time.Hour))
	// A bundle of two certificates.
	if err := os.WriteFile(f.ca, append(caPEM, caPEM...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.policy, []byte("package ghostunnel\nallow = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.certSHA, f.caSHA, f.policySHA = mSHA(t, f.cert), mSHA(t, f.ca), mSHA(t, f.policy)
	return f
}

func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// entry is one material object; sha is a hash or "null".
func entry(kind, path, sha string) string {
	if sha != "null" {
		sha = `"` + sha + `"`
	}
	return fmt.Sprintf(`{"material":"%s","path":%s,"sha256":%s}`, kind, jstr(path), sha)
}

func (f *mFiles) entries() string {
	return "[" + strings.Join([]string{entry("cert", f.cert, f.certSHA), entry("key", f.key, "null"), entry("ca", f.ca, f.caSHA), entry("policy", f.policy, f.policySHA)}, ",") + "]"
}

// mConfig is a start line's config; sandbox is the sandbox_state and
// accepted the sandbox_accepted, "" standing for null. The binary is the
// stand-in executable at mBinaryPath with its hash (binaryexpected_test.go).
func mConfig(material string, tickets, verifyOnResume bool, sandbox, accepted string) string {
	return mConfigBinary(material, tickets, verifyOnResume, sandbox, accepted, mBinaryEntry(mBinaryPath, mBinarySHA))
}

// mConfigBinary is mConfig with the config.binary object given.
func mConfigBinary(material string, tickets, verifyOnResume bool, sandbox, accepted, binary string) string {
	acc := "null"
	if accepted != "" {
		acc = jstr(accepted)
	}
	return fmt.Sprintf(`{"mode":"server","listen":"localhost:8443","target":"localhost:8080","proxy_protocol":"off","status_listen":null,"status_client_cert":false,"pprof_cmdline_redacted":true,"shutdown_requires_client_cert":true,"session_tickets":%t,"verify_on_resume":%t,"acl":["allow-cn:client.example"],"lifetime_cap_seconds":0,"sandbox_state":%s,"sandbox_accepted":%s,"material":%s,"binary":%s}`, tickets, verifyOnResume, jstr(sandbox), acc, material, binary)
}

func mHdr(kind string, seq int, at string) string {
	return fmt.Sprintf(`{"kind":"%s","version":1,"sequence":%d,"at":"%s"`, kind, seq, at)
}

func mStart(seq int, at string, boot int, config string) string {
	return fmt.Sprintf(`%s,"boot":%d,"pid":4242,"config":%s}`, mHdr("start", seq, at), boot, config)
}

func mReload(seq int, at string, outcome string, serving bool, material string) string {
	errv := "null"
	if outcome == "failed" {
		errv = `"open: permission denied"`
	}
	return fmt.Sprintf(`%s,"outcome":"%s","error":%s,"serving":%t,"material":%s}`, mHdr("reload", seq, at), outcome, errv, serving, material)
}

func mRenumber(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		s := strings.Index(line, `"sequence":`) + len(`"sequence":`)
		e := s + strings.Index(line[s:], ",")
		out[i] = line[:s] + fmt.Sprint(i+1) + line[e:]
	}
	return out
}

// mTick writes a tick line: the header and nothing else.
func mTick(seq int, at string) string {
	return mHdr("tick", seq, at) + "}"
}

// mFreshTick is the tick one second before materialNow that materialTree
// appends to every boot, so that tick-fresh holds over trees whose lines
// are an hour old.
const mFreshTick = "2026-09-24T11:59:59Z"

// mWithTick is lines followed by the fresh tick, in a new slice.
func mWithTick(lines []string) []string {
	return append(append([]string{}, lines...), mTick(0, mFreshTick))
}

func materialTree(t *testing.T, lines ...string) string {
	t.Helper()
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(mRenumber(mWithTick(lines))...))
	return root
}

// materialHealthy is a boot that loaded the files and reloaded them once.
func materialHealthy(f *mFiles) []string {
	return []string{
		mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(f.entries(), true, true, "applied", "")),
		mReload(2, "2026-09-24T11:30:00Z", "ok", true, f.entries()),
	}
}

func materialRun(t *testing.T, root string) []Finding {
	t.Helper()
	return materialRunWith(t, root, MaterialChecks{})
}

// materialSorted sorts findings by check and subject.
func materialSorted(got []Finding) []Finding {
	sort.Slice(got, func(i, j int) bool {
		if got[i].Check != got[j].Check {
			return got[i].Check < got[j].Check
		}
		return got[i].Subject < got[j].Subject
	})
	return got
}

func materialWant(t *testing.T, got []Finding, want ...Finding) {
	t.Helper()
	sort.Slice(want, func(i, j int) bool {
		if want[i].Check != want[j].Check {
			return want[i].Check < want[j].Check
		}
		return want[i].Subject < want[j].Subject
	})
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings\n got %v\nwant %v", got, want)
	}
}

func TestMaterialIdentifiers(t *testing.T) {
	want := []string{"trace-readable", "material-loaded", "binary-expected", "key-private", "reload-succeeded", "sandbox-applied", "resumption-bound", "tick-fresh", "trace-consistent", "boot-ambiguous", "boot-ended"}
	if got := (MaterialChecks{}).Identifiers(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("identifiers %v, want %v", got, want)
	}
	ring := (MaterialChecks{}).RingIdentifiers()
	if fmt.Sprint(ring) != fmt.Sprint([]string{"surface-disagree:admin", "surface-disagree:tunnel"}) {
		t.Fatalf("ring identifiers %v", ring)
	}
}

func TestMaterialHealthyTreeYieldsNothing(t *testing.T) {
	f := mMaterial(t)
	materialWant(t, materialRun(t, materialTree(t, materialHealthy(f)...)))
	// Without any reload, also nothing. With an empty material set,
	// material-loaded has nothing to compare and says nothing; key-private
	// has no key to show private and fails (keyprivate_test.go): the proxy
	// lists its key on every start line, so a list without one is not its.
	materialWant(t, materialRun(t, materialTree(t, materialHealthy(f)[0])))
	materialWant(t, materialRun(t, materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig("[]", false, false, "applied", "")))), Finding{"key-private", "none"})
}

func TestMaterialTickFresh(t *testing.T) {
	// The healthy tree without materialTree's fresh tick: the reference is
	// the start line, an hour before now (the reload at 11:30 is not a
	// tick), and the member's own -tick-max-age is what forgives it.
	f := mMaterial(t)
	root := t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(mRenumber(materialHealthy(f))...))
	materialWant(t, materialRun(t, root), Finding{"tick-fresh", "2026-09-24T11:00:00Z"})
	materialWant(t, materialRunWith(t, root, MaterialChecks{TunnelMargins: surfaceMargins{TickMaxAge: 2 * time.Hour}}))
	// A tick 31 s old is stale; 30 s old is not.
	root = t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(mRenumber(append(materialHealthy(f), mTick(0, "2026-09-24T11:59:29Z")))...))
	materialWant(t, materialRun(t, root), Finding{"tick-fresh", "2026-09-24T11:59:29Z"})
	root = t.TempDir()
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(mRenumber(append(materialHealthy(f), mTick(0, "2026-09-24T11:59:30Z")))...))
	materialWant(t, materialRun(t, root))
}

func TestMaterialOnDiskDiffersFromLoaded(t *testing.T) {
	f := mMaterial(t)
	root := materialTree(t, materialHealthy(f)...)
	// The certificate on disk is replaced after the last reload.
	mWriteCert(t, f.cert, f.key, mNow(t).Add(-time.Hour), mNow(t).Add(time.Hour))
	materialWant(t, materialRun(t, root), Finding{"material-loaded", "cert"})
	// A reload that loaded the new certificate makes it the one loaded.
	f.certSHA = mSHA(t, f.cert)
	lines := append(materialHealthy(f)[:1], mReload(2, "2026-09-24T11:30:00Z", "ok", true, "["+entry("cert", f.cert, f.certSHA)+"]"))
	lines[0] = mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(strings.Replace(f.entries(), f.certSHA, strings.Repeat("0", 64), 1), true, true, "applied", ""))
	materialWant(t, materialRun(t, materialTree(t, lines...)))
	// The policy on disk changed.
	f = mMaterial(t)
	root = materialTree(t, materialHealthy(f)...)
	if err := os.WriteFile(f.policy, []byte("package ghostunnel\nallow = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRun(t, root), Finding{"material-loaded", "policy"})
}

func TestMaterialFilesMissingOrUnreadable(t *testing.T) {
	f := mMaterial(t)
	root := materialTree(t, materialHealthy(f)...)
	if err := os.Remove(f.key); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRun(t, root), Finding{"material-loaded", "key"}, Finding{"key-private", "stat"})
	if err := os.Remove(f.cert); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRun(t, root), Finding{"material-loaded", "cert"}, Finding{"material-loaded", "key"}, Finding{"key-private", "stat"})
	// A key that is a directory is not a key file.
	if err := os.Mkdir(f.key, 0o755); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRun(t, root), Finding{"material-loaded", "cert"}, Finding{"material-loaded", "key"}, Finding{"key-private", "not-regular"})
}

func TestMaterialEntriesIncomplete(t *testing.T) {
	f := mMaterial(t)
	// A certificate with no hash recorded.
	entries := strings.Replace(f.entries(), `"sha256":"`+f.certSHA+`"`, `"sha256":null`, 1)
	materialWant(t, materialRun(t, materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(entries, true, true, "applied", "")))), Finding{"material-loaded", "cert"})
	// A CA bundle with no path.
	entries = strings.Replace(f.entries(), jstr(f.ca), `""`, 1)
	materialWant(t, materialRun(t, materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(entries, true, true, "applied", "")))), Finding{"material-loaded", "ca"})
	// A key with no path.
	entries = strings.Replace(f.entries(), jstr(f.key), `""`, 1)
	materialWant(t, materialRun(t, materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(entries, true, true, "applied", "")))), Finding{"material-loaded", "key"}, Finding{"key-private", "no-path"})
}

func TestMaterialValidityWindow(t *testing.T) {
	now := mNow(t)
	f := mMaterial(t)
	mWriteCert(t, f.cert, f.key, now.Add(-48*time.Hour), now.Add(-time.Hour))
	f.certSHA = mSHA(t, f.cert)
	materialWant(t, materialRun(t, materialTree(t, materialHealthy(f)...)), Finding{"material-loaded", "cert"})
	f = mMaterial(t)
	mWriteCert(t, f.cert, f.key, now.Add(time.Hour), now.Add(48*time.Hour))
	f.certSHA = mSHA(t, f.cert)
	materialWant(t, materialRun(t, materialTree(t, materialHealthy(f)...)), Finding{"material-loaded", "cert"})
	// One expired certificate in the bundle is enough.
	f = mMaterial(t)
	old := mWriteCert(t, filepath.Join(f.dir, "old.pem"), filepath.Join(f.dir, "old-key.pem"), now.Add(-48*time.Hour), now.Add(-time.Hour))
	ca, err := os.ReadFile(f.ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.ca, append(ca, old...), 0o644); err != nil {
		t.Fatal(err)
	}
	f.caSHA = mSHA(t, f.ca)
	materialWant(t, materialRun(t, materialTree(t, materialHealthy(f)...)), Finding{"material-loaded", "ca"})
	// A CA file that holds no certificate cannot be judged.
	f = mMaterial(t)
	if err := os.WriteFile(f.ca, []byte("not pem at all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.caSHA = mSHA(t, f.ca)
	materialWant(t, materialRun(t, materialTree(t, materialHealthy(f)...)), Finding{"material-loaded", "ca"})
	// A certificate file whose PEM block does not parse.
	f = mMaterial(t)
	if err := os.WriteFile(f.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), 0o644); err != nil {
		t.Fatal(err)
	}
	f.certSHA = mSHA(t, f.cert)
	materialWant(t, materialRun(t, materialTree(t, materialHealthy(f)...)), Finding{"material-loaded", "cert"})
}

func TestMaterialReloadSucceeded(t *testing.T) {
	f := mMaterial(t)
	lines := materialHealthy(f)
	lines[1] = mReload(2, "2026-09-24T11:30:00Z", "failed", true, f.entries())
	materialWant(t, materialRun(t, materialTree(t, lines...)), Finding{"reload-succeeded", "failed-and-serving"}, Finding{"reload-succeeded", "last-reload-failed"})
	// A failed reload that stopped serving is the right outcome, and the
	// last reload having failed is still a finding.
	lines[1] = mReload(2, "2026-09-24T11:30:00Z", "failed", false, f.entries())
	materialWant(t, materialRun(t, materialTree(t, lines...)), Finding{"reload-succeeded", "last-reload-failed"})
	// A failure that kept serving followed by a success: the failure stands.
	lines = append(materialHealthy(f), mReload(3, "2026-09-24T11:40:00Z", "failed", true, f.entries()), mReload(4, "2026-09-24T11:50:00Z", "ok", true, f.entries()))
	materialWant(t, materialRun(t, materialTree(t, lines...)), Finding{"reload-succeeded", "failed-and-serving"})
}

// materialRunWith is materialRun with the observer's own sandbox
// acceptance and OS injected, so the rule is proved on every host.
func materialRunWith(t *testing.T, root string, checks MaterialChecks) []Finding {
	t.Helper()
	if checks.Live == nil {
		// Nobody is live in an empty process table: the trees here name
		// pid 4242, which may or may not be a process on this host.
		checks.Live = procLiveness(blTable(t, 4242))
	}
	if checks.ExpectBinarySHA256 == "" {
		// The stand-in executable every mConfig start line names, and
		// the hash it records (binaryexpected_test.go).
		checks.ExpectBinarySHA256 = mBinarySHA
	}
	if checks.KeyProbe == nil {
		// The key files here are the test's own, on whatever host runs
		// it: key-private sees them as root's, 0600, asked by a member
		// that is nobody's owner (keyprivate_test.go holds the rule).
		checks.KeyProbe = mRootKeyProbe
	}
	got := materialSorted(checks.Run(&Config{TracesRoot: root, Now: mNow(t)}, &State{}, nil))
	ids := map[string]bool{}
	for _, id := range checks.Identifiers() {
		ids[id] = true
	}
	for _, f := range got {
		if !ids[f.Check] {
			t.Fatalf("finding %v names an undeclared identifier", f)
		}
	}
	return got
}

// TestMaterialSandboxApplied is the rule of sandbox-applied over every
// state the start line can carry, every acceptance it can carry beside it,
// and every value of this observer's own -accept-no-sandbox, on an
// observer whose OS is injected as windows so the three-way agreement can
// be made and broken on any host. The sandbox itself is outside this
// package; what is judged is that ghostunnel reported an applied sandbox,
// or that the platform has none and an operator said so on both sides of
// the boundary for this very OS.
func TestMaterialSandboxApplied(t *testing.T) {
	f := mMaterial(t)
	const goos = "windows"
	cases := []struct {
		state, accepted, flag string
		want                  []string // subjects of sandbox-applied; none passes
	}{
		// Applied passes without a flag; with one the acceptance is stale.
		{"applied", "", "", nil},
		{"applied", "", goos, []string{"stale-acceptance"}},
		{"applied", "", "darwin", []string{"stale-acceptance"}},
		// Unsupported passes only on three-way agreement.
		{"unsupported", goos, goos, nil},
		{"unsupported", "", "", []string{"unsupported"}},
		{"unsupported", goos, "", []string{"unsupported:not-accepted-by-observer"}},
		{"unsupported", "", goos, []string{"unsupported:not-accepted-by-proxy"}},
		{"unsupported", "darwin", goos, []string{"unsupported:acceptance-mismatch"}},
		{"unsupported", goos, "darwin", []string{"unsupported:acceptance-not-this-os"}},
		{"unsupported", "darwin", "darwin", []string{"unsupported:acceptance-not-this-os"}},
		{"unsupported", "Windows", goos, []string{"unsupported:acceptance-mismatch"}},
		{"unsupported", goos, "Windows", []string{"unsupported:acceptance-not-this-os"}},
		// Every other state fails on the state, and a flag beside it is
		// stale as well: the facility exists there.
		{"disabled", "", "", []string{"disabled"}},
		{"disabled", "", goos, []string{"disabled", "stale-acceptance"}},
		{"failed", "", "", []string{"failed"}},
		{"failed", "", goos, []string{"failed", "stale-acceptance"}},
		{"skipped", "", "", []string{"skipped"}},
		{"skipped", "", goos, []string{"skipped", "stale-acceptance"}},
	}
	for _, c := range cases {
		name := fmt.Sprintf("state=%s accepted=%q flag=%q", c.state, c.accepted, c.flag)
		t.Run(name, func(t *testing.T) {
			root := materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(f.entries(), true, true, c.state, c.accepted)))
			var want []Finding
			for _, s := range c.want {
				want = append(want, Finding{"sandbox-applied", s})
			}
			materialWant(t, materialRunWith(t, root, MaterialChecks{AcceptNoSandbox: c.flag, GOOS: goos}), want...)
		})
	}
	// An observer that does not know its OS can agree with nobody.
	root := materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(f.entries(), true, true, "unsupported", goos)))
	materialWant(t, materialRunWith(t, root, MaterialChecks{AcceptNoSandbox: goos}), Finding{"sandbox-applied", "unsupported:acceptance-not-this-os"})
	// And the rule as a function, for the flag parser and the docs to
	// cite: the same table, without a tree.
	for _, c := range cases {
		var accepted *string
		if c.accepted != "" {
			a := c.accepted
			accepted = &a
		}
		if got := sandboxSubjects(c.state, accepted, c.flag, goos); fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Fatalf("sandboxSubjects(%s, %q, %q, %s) = %v, want %v", c.state, c.accepted, c.flag, goos, got, c.want)
		}
	}
}

// TestMaterialAcceptNoSandboxFlag is the parser's refusal: the flag is
// accepted only when it names the OS this observer runs on exactly, and
// never on linux, where the facility exists and there is nothing to accept.
func TestMaterialAcceptNoSandboxFlag(t *testing.T) {
	for _, c := range []struct {
		value, goos string
		ok          bool
	}{
		{"", "linux", true},
		{"", "windows", true},
		{"windows", "windows", true},
		{"darwin", "darwin", true},
		{"linux", "linux", false},
		{"windows", "linux", false},
		{"darwin", "windows", false},
		{"Windows", "windows", false},
		{"windows ", "windows", false},
		{"windows", "", false},
	} {
		err := acceptNoSandboxValid(c.value, c.goos)
		if (err == nil) != c.ok {
			t.Fatalf("acceptNoSandboxValid(%q, %q) = %v, want ok=%v", c.value, c.goos, err, c.ok)
		}
	}
	// Through parseFlags on this host: the value must be this OS, and on
	// linux no value is accepted.
	base := []string{"-heartbeat-max-age", "30s", "-slot-owners", "tunnel=a,admin=b,material=c,super=d", "-expect-binary-sha256", strings.Repeat("a", 64)}
	cfg, _, _, err := parseFlags(base)
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if local := cfg.Local.(MaterialChecks); local.AcceptNoSandbox != "" || local.GOOS != runtime.GOOS {
		t.Fatalf("defaults carry %+v", local)
	}
	if cfg.Window != 3 {
		t.Fatalf("the default window is %d, want the deployment's 3 (SPEC 6)", cfg.Window)
	}
	cfg, _, _, err = parseFlags(append(base, "-accept-no-sandbox="+runtime.GOOS))
	if runtime.GOOS == "linux" {
		if err == nil {
			t.Fatalf("linux accepted an acceptance")
		}
	} else {
		if err != nil {
			t.Fatalf("own OS refused: %v", err)
		}
		if local := cfg.Local.(MaterialChecks); local.AcceptNoSandbox != runtime.GOOS || local.GOOS != runtime.GOOS {
			t.Fatalf("flag not carried: %+v", local)
		}
	}
	for _, bad := range []string{"plan9", strings.ToUpper(runtime.GOOS), runtime.GOOS + " ", "linux"} {
		if _, _, _, err := parseFlags(append(base, "-accept-no-sandbox="+bad)); err == nil {
			t.Fatalf("-accept-no-sandbox=%q accepted on %s", bad, runtime.GOOS)
		}
	}
}

func TestMaterialResumptionBound(t *testing.T) {
	f := mMaterial(t)
	materialWant(t, materialRun(t, materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(f.entries(), true, false, "applied", "")))), Finding{"resumption-bound", ""})
	materialWant(t, materialRun(t, materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(f.entries(), false, false, "applied", "")))))
	materialWant(t, materialRun(t, materialTree(t, mStart(1, "2026-09-24T11:00:00Z", 1, mConfig(f.entries(), false, true, "applied", "")))))
}

// materialBootFail is what a current boot that cannot be judged yields:
// every check over it fails, and trace-readable names where.
// trace-consistent compares what was read and boot-ambiguous asks the
// process table; neither is over the current boot.
func materialBootFail(subject string) []Finding {
	out := []Finding{{"trace-readable", subject}}
	for _, id := range (MaterialChecks{}).Identifiers() {
		if id != "trace-readable" && id != "trace-consistent" && id != "boot-ambiguous" && id != "boot-ended" {
			out = append(out, Finding{id, ""})
		}
	}
	return out
}

// materialAllFail is what an unreadable trace yields: materialBootFail,
// and trace-consistent, which could not compare anything.
func materialAllFail(subject string) []Finding {
	return append(materialBootFail(subject), Finding{"trace-consistent", ""})
}

func TestMaterialUnreadableTraceFailsEveryCheck(t *testing.T) {
	f := mMaterial(t)
	materialWant(t, materialRun(t, ""), materialAllFail("gt")...)
	materialWant(t, materialRun(t, filepath.Join(t.TempDir(), "gt")), materialAllFail("gt")...)
	materialWant(t, materialRun(t, t.TempDir()), materialAllFail("gt")...)
	root := materialTree(t, materialHealthy(f)...)
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	materialWant(t, materialRun(t, root), materialAllFail("README")...)
	lines := materialHealthy(f)
	lines[1] = strings.Replace(lines[1], `"serving":true`, `"serving":1`, 1)
	materialWant(t, materialRun(t, materialTree(t, lines...)), materialAllFail("0000000001/0000000001.trace:2")...)
	root = materialTree(t, materialHealthy(f)...)
	if err := os.Mkdir(filepath.Join(root, "0000000002"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The empty boot cannot be shown dead and the older boot's process
	// is live: ambiguous as well.
	materialWant(t, materialRun(t, root), append(materialBootFail("0000000002"), Finding{"boot-ambiguous", "0000000001,0000000002"})...)
}

// TestMaterialRunJudgesTheRing is the wiring of the checks this member
// makes beyond its own surface: the other surfaces against their owners'
// accounts, every boot's process, and the trace against what was read
// last cycle.
func TestMaterialRunJudgesTheRing(t *testing.T) {
	f := mMaterial(t)
	run := func(root string, checks MaterialChecks, st *State, peers map[string]PeerView) []Finding {
		return materialSorted(checks.Run(&Config{TracesRoot: root, Now: mNow(t)}, st, peers))
	}
	checks := MaterialChecks{Live: procLiveness(blTable(t, 4242)), KeyProbe: mRootKeyProbe, ExpectBinarySHA256: mBinarySHA}
	peers := map[string]PeerView{}
	for _, o := range []string{"tunnel", "admin"} {
		peers[o] = PeerView{Verdict: VerdictAlive, Checks: surfaceIdentifiers(o)}
	}
	root := materialTree(t, materialHealthy(f)...)
	materialWant(t, run(root, checks, &State{}, peers))
	// The admin member stopped listing pprof-cmdline-redacted.
	peers["admin"] = PeerView{Verdict: VerdictAlive, Checks: []string{"status-listener-bound", "shutdown-authorized", "status-listener-up"}}
	materialWant(t, run(root, checks, &State{}, peers), Finding{"surface-disagree", "admin:pprof-cmdline-redacted"})
	peers["admin"] = PeerView{Verdict: VerdictAlive, Checks: surfaceIdentifiers("admin")}
	// A second boot whose process is live beside the current one.
	root = materialTree(t, materialHealthy(f)...)
	second := strings.Replace(mStart(1, "2026-09-24T11:30:00Z", 2, mConfig(f.entries(), true, true, "applied", "")), `"pid":4242`, `"pid":4343`, 1)
	gtWriteSegment(t, root, "0000000002", "0000000001.trace", gtJoin(second, mTick(2, mFreshTick)))
	table := t.TempDir()
	for _, pid := range []string{"4242", "4343"} {
		if err := os.Mkdir(filepath.Join(table, pid), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	materialWant(t, run(root, MaterialChecks{Live: procLiveness(table), KeyProbe: mRootKeyProbe, ExpectBinarySHA256: mBinarySHA}, &State{}, peers), Finding{"boot-ambiguous", "0000000001,0000000002"})
	// The current boot rewritten under this member between two cycles.
	root = materialTree(t, materialHealthy(f)...)
	st := &State{}
	materialWant(t, run(root, checks, st, peers))
	lines := materialHealthy(f)
	lines[1] = strings.Replace(lines[1], `"at":"2026-09-24T11:30:00Z"`, `"at":"2026-09-24T11:30:01Z"`, 1)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(mRenumber(mWithTick(lines))...))
	materialWant(t, run(root, checks, st, peers), Finding{"trace-consistent", "0000000001/0000000001.trace"})
}
