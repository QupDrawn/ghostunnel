package ringtrace

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	status := "127.0.0.1:6060"
	cert := "b" + strings.Repeat("1", 63)
	return Config{
		Mode: "server", Listen: "0.0.0.0:8443", Target: "127.0.0.1:8080", ProxyProtocol: ProxyProtocolOff,
		StatusListen: &status, StatusClientCert: false,
		SessionTickets: false, VerifyOnResume: true, ACL: []string{"allow-all"}, LifetimeCapSeconds: 300, SandboxState: SandboxApplied,
		Material: []Material{
			{Material: "cert", Path: "/etc/gt/server.crt", SHA256: &cert},
			{Material: "key", Path: "/etc/gt/server.key"},
		},
		Binary: testBinary,
	}
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 24, 10, 7, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func openTestEmitter(t *testing.T, root string, o Options) *Emitter {
	t.Helper()
	if o.Now == nil {
		o.Now = fixedClock()
	}
	if o.Config.Mode == "" {
		o.Config = testConfig()
	}
	if o.PID == 0 {
		o.PID = 4242
	}
	e, err := Open(root, o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return e
}

// readLines returns the lines of a segment's content (the bytes before its
// first NUL: a live segment is pre-extended and its tail is unwritten).
func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := ReadSegmentContent(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
	}
	return bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
}

// segmentContent reads a segment by the segment rule and fails the test on
// an error.
func segmentContent(t *testing.T, path string) []byte {
	t.Helper()
	data, err := ReadSegmentContent(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fileSize is the segment's size on disk, which is MaxSegmentBytes while it
// is live and its content length once it is closed.
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// requireExactSize checks that a closed segment holds exactly its content:
// its size is its content length and it has no NUL.
func requireExactSize(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		t.Fatalf("%s: a closed segment holds a NUL", path)
	}
	content := segmentContent(t, path)
	if !bytes.Equal(raw, content) || fileSize(t, path) != int64(len(content)) {
		t.Fatalf("%s: size %d, content %d bytes: a closed segment is not exactly its content", path, fileSize(t, path), len(content))
	}
	return content
}

func TestEmitterFirstBootWritesStartLine(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{})
	if e.Boot() != 1 {
		t.Fatalf("first boot must be 1, got %d", e.Boot())
	}
	seg := filepath.Join(root, "0000000001", "0000000001.trace")
	lines := readLines(t, seg)
	if len(lines) != 1 {
		t.Fatalf("want exactly the start line, got %d lines", len(lines))
	}
	rec, err := DecodeLine(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	st, ok := rec.Body.(*Start)
	if !ok || rec.Sequence != 1 || st.Boot != 1 || st.PID != 4242 || st.Config.Listen != "0.0.0.0:8443" {
		t.Fatalf("bad start record: %#v", rec)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Emit(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"}); err == nil {
		t.Fatal("Emit after Close must fail")
	}
}

func TestEmitterSequenceIsMonotonicAndBootIsDurable(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{})
	for i := 1; i <= 3; i++ {
		seq, err := e.Emit(&Accept{Conn: int64(i), Listener: "a:1", Remote: "b:2"})
		if err != nil {
			t.Fatal(err)
		}
		if seq != int64(i+1) {
			t.Fatalf("sequence: want %d got %d", i+1, seq)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := openTestEmitter(t, root, Options{})
	if e2.Boot() != 2 {
		t.Fatalf("second process must take boot 2, got %d", e2.Boot())
	}
	seq, err := e2.Emit(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"})
	if err != nil || seq != 2 {
		t.Fatalf("sequence restarts per process: want 2 got %d (%v)", seq, err)
	}
	e2.Close()

	// A stray directory number is not reused: boot 7 present means next is 8.
	if err := os.Mkdir(filepath.Join(root, "0000000007"), 0o755); err != nil {
		t.Fatal(err)
	}
	e3 := openTestEmitter(t, root, Options{})
	if e3.Boot() != 8 {
		t.Fatalf("boot must be highest+1 = 8, got %d", e3.Boot())
	}
	e3.Close()

	tr, err := Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	var nums []int64
	for _, b := range tr.Boots {
		nums = append(nums, b.Number)
	}
	// Boot 7 is an empty directory: a process that died between creating
	// its directory and writing its first line. That is benign and reads as
	// a boot with no records; it never makes the tree malformed.
	if want := []int64{1, 2, 7, 8}; len(nums) != 4 || nums[0] != 1 || nums[1] != 2 || nums[2] != 7 || nums[3] != 8 {
		t.Fatalf("boots: want %v got %v", want, nums)
	}
	if len(tr.Boots[2].Records) != 0 || len(tr.Boots[2].Segments) != 0 {
		t.Fatalf("boot 7 must be empty: %#v", tr.Boots[2])
	}
	if last := tr.Latest(); last == nil || last.Sequence != 1 || last.Body.(*Start).Boot != 8 {
		t.Fatalf("Latest is the last complete line of boot 8: %#v", last)
	}
}

func TestEmitterRefusesStrayEntriesInRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, Options{Config: testConfig(), PID: 1, Now: fixedClock()}); err == nil {
		t.Fatal("Open must refuse a root holding anything but boot directories")
	}
}

func TestEmitterRotation(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{MaxSegmentBytes: 400})
	for i := 1; i <= 20; i++ {
		if _, err := e.Emit(&Accept{Conn: int64(i), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "0000000001")
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) < 3 {
		t.Fatalf("expected several segments, got %d", len(des))
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	sort.Strings(names)
	if names[0] != "0000000001.trace" {
		t.Fatalf("first segment must be 0000000001.trace, got %v", names)
	}
	// Every segment is named by the sequence of its first line and every
	// segment ends in LF (after Close every segment is exactly its content).
	for _, n := range names {
		data := requireExactSize(t, filepath.Join(dir, n))
		if !bytes.HasSuffix(data, []byte("\n")) {
			t.Fatalf("%s does not end in LF", n)
		}
		if int64(len(data)) > 400+MaxLineBytes {
			t.Fatalf("%s exceeds the segment bound by more than one line", n)
		}
		first, err := DecodeLine(bytes.Split(data, []byte("\n"))[0])
		if err != nil {
			t.Fatal(err)
		}
		if want := SegmentName(first.Sequence); want != n {
			t.Fatalf("segment %s holds first sequence %d (want name %s)", n, first.Sequence, want)
		}
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("Read after rotation: %v", err)
	}
	b := tr.Boots[0]
	if len(b.Records) != 21 || b.Records[20].Sequence != 21 || len(b.Segments) != len(names) {
		t.Fatalf("reader: %d records, last seq %d, %d segments", len(b.Records), b.Records[len(b.Records)-1].Sequence, len(b.Segments))
	}
	if last := tr.Latest(); last == nil || last.Sequence != 21 {
		t.Fatalf("Latest must be sequence 21, got %#v", last)
	}
}

func TestEmitterOpenFailsClosed(t *testing.T) {
	// The root does not exist.
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), Options{Config: testConfig(), PID: 1, Now: fixedClock()}); err == nil {
		t.Fatal("Open must fail on a missing root")
	}
	// The root is a file.
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f, Options{Config: testConfig(), PID: 1, Now: fixedClock()}); err == nil {
		t.Fatal("Open must fail when the root is a regular file")
	}
	// The boot directory it would create exists as a file.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "0000000001"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, Options{Config: testConfig(), PID: 1, Now: fixedClock()}); err == nil {
		t.Fatal("Open must fail when a boot entry is not a directory")
	}
	// An invalid config never opens.
	if _, err := Open(t.TempDir(), Options{Config: Config{}, PID: 1, Now: fixedClock()}); err == nil {
		t.Fatal("Open must fail on an invalid config")
	}
}

func TestEmitterWriteErrorIsReturnedAndSticky(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{})
	defer e.Close()
	boom := errors.New("disk full")
	e.failWrites = boom
	if _, err := e.Emit(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"}); !errors.Is(err, boom) {
		t.Fatalf("Emit must return the write error, got %v", err)
	}
	e.failWrites = nil
	if _, err := e.Emit(&Accept{Conn: 2, Listener: "a:1", Remote: "b:2"}); err == nil {
		t.Fatal("after a failed write the emitter must stay failed")
	}
	if e.Err() == nil {
		t.Fatal("Err must report the sticky failure")
	}
	// Nothing after the start line reached the disk.
	lines := readLines(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	if len(lines) != 1 {
		t.Fatalf("want 1 line on disk, got %d", len(lines))
	}
}

func TestEmitterShortWriteIsAnError(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{})
	defer e.Close()
	e.shortWrites = true
	if _, err := e.Emit(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"}); err == nil {
		t.Fatal("a short write must be an error")
	}
	if _, err := e.Emit(&Accept{Conn: 2, Listener: "a:1", Remote: "b:2"}); err == nil {
		t.Fatal("a short write must leave the emitter failed")
	}
}

func TestEmitterRefusesInvalidEvent(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{})
	defer e.Close()
	if _, err := e.Emit(&ACL{Conn: 1, Decision: "maybe", Rule: "r", Reason: "x"}); err == nil {
		t.Fatal("an invalid event must be refused")
	}
	// A refused event consumes no sequence number and does not fail the emitter.
	seq, err := e.Emit(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"})
	if err != nil || seq != 2 {
		t.Fatalf("want sequence 2 after a refused event, got %d (%v)", seq, err)
	}
}

func TestEmitterNeverWritesSecrets(t *testing.T) {
	root := t.TempDir()
	const storepass = "hunter2-storepass-canary"
	const pin = "314159-pkcs11-pin-canary"
	const keyPEM = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIIA=\n-----END EC PRIVATE KEY-----"
	const cmdline = "ghostunnel server --storepass " + storepass
	// A caller that mistakenly puts key material into a field is refused
	// rather than recorded.
	e := openTestEmitter(t, root, Options{})
	if _, err := e.Emit(&Shutdown{Source: "signal", Authorized: true, Detail: keyPEM}); err == nil {
		t.Fatal("PEM in a field must be refused")
	}
	// The ordinary run.
	cert := "b" + strings.Repeat("1", 63)
	for _, b := range []Body{
		&Accept{Conn: 1, Listener: "0.0.0.0:8443", Remote: "10.0.0.7:51234"},
		&Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: "TLS1.3", Peer: &Peer{Subject: "CN=c", Issuer: "CN=ca", Serial: "1", SANs: []string{"dns:c"}, Fingerprint: cert}},
		&ACL{Conn: 1, Decision: "allow", Rule: "allow-cn", Reason: "matched"},
		&Close{Conn: 1, Reason: "eof", DurationMS: 10},
		&Reload{Outcome: "failed", Error: strp("open /etc/gt/server.key: permission denied"), Serving: false, Material: []Material{{Material: "key", Path: "/etc/gt/server.key"}}},
		&Shutdown{Source: "signal", Authorized: true, Detail: "SIGTERM"},
	} {
		if _, err := e.Emit(b); err != nil {
			t.Fatal(err)
		}
	}
	e.Close()
	data := segmentContent(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	for _, secret := range []string{storepass, pin, "PRIVATE KEY", cmdline, "MHcCAQEEIIA="} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("trace contains %q", secret)
		}
	}
}

func strp(s string) *string { return &s }

func TestEmitterConcurrentEmitsAreWholeAndConsecutive(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{MaxSegmentBytes: 2048, Sync: SyncOnRotateAndClose})
	var wg sync.WaitGroup
	const n = 200
	seqs := make([]int64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seq, err := e.Emit(&Accept{Conn: int64(i + 1), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"})
			if err != nil {
				t.Error(err)
			}
			seqs[i] = seq
		}(i)
	}
	wg.Wait()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, s := range seqs {
		if s != int64(i+2) {
			t.Fatalf("sequences not consecutive: %v", seqs)
		}
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := len(tr.Boots[0].Records); got != n+1 {
		t.Fatalf("want %d records, got %d", n+1, got)
	}
}

// TestEmitterLockIsExclusive: an emitter holds an exclusive lock on
// gt/lock for its lifetime, so a second emitter under the same root cannot
// open, take the next boot and be the one the readers judge. The lock is
// released on Close (and by the OS when the process dies), after which a
// new emitter opens.
func TestEmitterLockIsExclusive(t *testing.T) {
	root := t.TempDir()
	first := openTestEmitter(t, root, Options{})
	if _, err := os.Stat(filepath.Join(root, "lock")); err != nil {
		t.Fatalf("the lock file must exist under the root: %v", err)
	}
	second, err := Open(root, Options{Config: testConfig(), PID: 4243, Now: fixedClock()})
	if err == nil {
		second.Close()
		t.Fatal("a second Open under a held lock must fail")
	}
	if !strings.Contains(err.Error(), "lock") {
		t.Fatalf("the error must name the lock, got %v", err)
	}
	boots, err := listBoots(root)
	if err != nil || len(boots) != 1 {
		t.Fatalf("the refused Open must not have created a boot: %v %v", boots, err)
	}
	if _, err := Read(root); err != nil {
		t.Fatalf("the lock file is not a stray entry to the reader: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third := openTestEmitter(t, root, Options{PID: 4244})
	defer third.Close()
	if third.Boot() != 2 {
		t.Fatalf("after the first closed a new emitter opens, as boot 2, got %d", third.Boot())
	}
}

// TestEmitterLiveSegmentIsPreExtended: the live segment is pre-extended to
// MaxSegmentBytes when it is opened, so its size on disk is that from the
// start and only its content grows; after Emit returns, the content (the
// bytes before the first NUL) ends with that line, and everything after
// the content is unwritten zeros.
func TestEmitterLiveSegmentIsPreExtended(t *testing.T) {
	root := t.TempDir()
	const max = 1 << 20
	e := openTestEmitter(t, root, Options{MaxSegmentBytes: max})
	defer e.Close()
	path := filepath.Join(root, "0000000001", "0000000001.trace")
	if got := fileSize(t, path); got != max {
		t.Fatalf("live segment size %d, want MaxSegmentBytes %d from the start", got, max)
	}
	for i := 1; i <= 3; i++ {
		seq, err := e.Emit(&Accept{Conn: int64(i), Listener: "a:1", Remote: "b:2"})
		if err != nil {
			t.Fatal(err)
		}
		content := segmentContent(t, path)
		if len(content) == 0 || content[len(content)-1] != '\n' || int64(len(content)) >= max {
			t.Fatalf("content of %d bytes must be shorter than the segment and end in LF", len(content))
		}
		lines := bytes.Split(bytes.TrimSuffix(content, []byte("\n")), []byte("\n"))
		rec, err := DecodeLine(lines[len(lines)-1])
		if err != nil {
			t.Fatal(err)
		}
		if rec.Sequence != seq {
			t.Fatalf("after Emit returned the content ends with sequence %d, want %d", rec.Sequence, seq)
		}
		if got := fileSize(t, path); got != max {
			t.Fatalf("live segment size %d after Emit, want %d", got, max)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw[:len(content)], content) || bytes.Count(raw[len(content):], []byte{0}) != len(raw)-len(content) {
			t.Fatal("the segment is not its content followed by zeros")
		}
	}
}

// TestEmitterRotationAndCloseLeaveExactSizeSegments: a rotation truncates
// the segment it closes to its written length and Close does the same to
// the last one, so a closed segment is exactly its content with no NUL;
// while the emitter runs only the live segment is pre-extended; and the
// contents of all the segments, in order, are exactly the lines emitted.
func TestEmitterRotationAndCloseLeaveExactSizeSegments(t *testing.T) {
	root := t.TempDir()
	const max = 400
	e := openTestEmitter(t, root, Options{MaxSegmentBytes: max})
	// The mirror of what the emitter writes: the same clock, sequences and
	// bodies through the same encoder.
	clock := fixedClock()
	var want []byte
	line, err := EncodeLine(Record{Sequence: 1, At: clock(), Body: &Start{Boot: 1, PID: 4242, Config: testConfig()}})
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, line...)
	dir := filepath.Join(root, "0000000001")
	segments := func() []string {
		des, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, de := range des {
			names = append(names, de.Name())
		}
		sort.Strings(names)
		return names
	}
	for i := 1; i <= 20; i++ {
		body := &Accept{Conn: int64(i), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"}
		seq, err := e.Emit(body)
		if err != nil {
			t.Fatal(err)
		}
		line, err := EncodeLine(Record{Sequence: seq, At: clock(), Body: body})
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, line...)
		names := segments()
		for j, n := range names {
			path := filepath.Join(dir, n)
			if j == len(names)-1 {
				if got := fileSize(t, path); got != max {
					t.Fatalf("live segment %s: size %d, want %d", n, got, max)
				}
				continue
			}
			requireExactSize(t, path)
		}
	}
	names := segments()
	if len(names) < 3 {
		t.Fatalf("expected several segments, got %v", names)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for _, n := range names {
		got = append(got, requireExactSize(t, filepath.Join(dir, n))...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the segments' contents are not the lines emitted:\n got %d bytes\nwant %d bytes", len(got), len(want))
	}
}

// TestEmitterSyncCountPerSegment states what SyncCount counts: one fsync
// per segment opened (its pre-extension), one per group commit under
// SyncEveryLine (one per Emit when Emits are serial), and one per segment
// closed by a rotation or by Close. A rotation therefore costs two fsyncs
// and Open two; an Emit that does not rotate costs one.
func TestEmitterSyncCountPerSegment(t *testing.T) {
	for _, policy := range []SyncPolicy{SyncEveryLine, SyncOnRotateAndClose} {
		root := t.TempDir()
		e := openTestEmitter(t, root, Options{Sync: policy, MaxSegmentBytes: 400})
		perEmit := int64(0)
		if policy == SyncEveryLine {
			perEmit = 1
		}
		// Open: the first segment's pre-extension, then the start line's commit.
		if got, want := e.SyncCount(), 1+perEmit; got != want {
			t.Fatalf("policy %d: %d fsyncs after Open, want %d (pre-extension + start line)", policy, got, want)
		}
		dir := filepath.Join(root, "0000000001")
		count := func() int {
			des, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			return len(des)
		}
		rotations := 0
		for i := 1; i <= 20; i++ {
			before, segs := e.SyncCount(), count()
			if _, err := e.Emit(&Accept{Conn: int64(i), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"}); err != nil {
				t.Fatal(err)
			}
			want := before + perEmit
			if count() > segs {
				// A rotation: the close of the full segment and the
				// pre-extension of the new one, then the line's commit.
				rotations++
				want += 2
			}
			if got := e.SyncCount(); got != want {
				t.Fatalf("policy %d: Emit %d: %d fsyncs, want %d", policy, i, got, want)
			}
		}
		if rotations == 0 {
			t.Fatal("no rotation happened")
		}
		before := e.SyncCount()
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
		if got := e.SyncCount(); got != before+1 {
			t.Fatalf("policy %d: Close issued %d fsyncs, want 1", policy, got-before)
		}
	}
}

// withUmask022 sets the process umask to 022 for the test where the
// platform has one, so that a mode observed on disk is exactly the mode
// requested (0750 and 0640 have no bit in 022), and restores it after.
func withUmask022(t *testing.T) {
	t.Helper()
	if !hasPosixModes {
		return
	}
	old := setUmask(0o022)
	t.Cleanup(func() { setUmask(old) })
}

// assertMode requires that the entry at path was created with exactly the
// permission bits want. Where the platform reports POSIX modes the test
// runs under withUmask022, so the bits observed are the bits requested;
// elsewhere (Windows) nothing is observable and the requested constants,
// asserted by the caller, are the whole check.
func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if !hasPosixModes {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s: mode %04o, want %04o", path, got, want)
	}
}

// TestEmitterCreatesGroupReadableOnly: everything the emitter creates under
// the trace root is readable by the root's owner and group and by nobody
// else. The trace names every peer that presented a certificate, so the
// modes requested are 0750 for a directory and 0640 for a file (DirMode,
// FileMode), for the lock, the boot directory and every segment, the one
// a rotation opens included; and, where the platform reports it, that is
// the mode observed.
func TestEmitterCreatesGroupReadableOnly(t *testing.T) {
	if DirMode != 0o750 {
		t.Fatalf("DirMode is %04o, want 0750", DirMode)
	}
	if FileMode != 0o640 {
		t.Fatalf("FileMode is %04o, want 0640", FileMode)
	}
	withUmask022(t)
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{MaxSegmentBytes: 600})
	defer e.Close()
	// Enough lines to rotate once: the start line and the accepts exceed
	// 600 bytes well before the tenth.
	for i := 1; i <= 10; i++ {
		if _, err := e.Emit(&Accept{Conn: int64(i), Listener: "a:1", Remote: "b:2"}); err != nil {
			t.Fatal(err)
		}
	}
	bootDir := filepath.Join(root, BootName(1))
	assertMode(t, filepath.Join(root, LockName), FileMode)
	assertMode(t, bootDir, DirMode)
	entries, err := os.ReadDir(bootDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("%d segment(s) after ten lines at 600 bytes per segment; the rotation did not happen", len(entries))
	}
	for _, de := range entries {
		assertMode(t, filepath.Join(bootDir, de.Name()), FileMode)
	}
	// The mode is requested, not left to the umask: a wider umask cannot
	// widen it. Under umask 077 a second root gets 0700 and 0600, which
	// is narrower than requested and never wider.
	if hasPosixModes {
		setUmask(0o077)
		root2 := t.TempDir()
		e2 := openTestEmitter(t, root2, Options{})
		defer e2.Close()
		for _, p := range []string{filepath.Join(root2, LockName), filepath.Join(root2, BootName(1)), filepath.Join(root2, BootName(1), SegmentName(1))} {
			info, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got&^0o750 != 0 {
				t.Fatalf("%s: mode %04o has a bit outside 0750", p, got)
			}
		}
	}
}
