package ringtrace

// The group-commit tests: what one fsync covers, who waits on it, and who
// hears of its failure. They go through the sync seams (failSync,
// syncHook) and the sync counter, which are the emitter's only view of
// the disk that a test can see.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// contentLength is how many bytes of the segment f have been written: the
// length of its content by the segment rule (the segment is pre-extended,
// so its size on disk says nothing). The path is read afresh; f itself is
// not touched.
func contentLength(f *os.File) (int64, error) {
	content, err := ReadSegmentContent(f.Name())
	if err != nil {
		return 0, err
	}
	return int64(len(content)), nil
}

// syncRecorder is a syncHook that remembers how many bytes of the segment
// each completed fsync covered (the content length when the fsync began)
// and slows every fsync down so that concurrent callers pile up behind it.
type syncRecorder struct {
	delay   time.Duration
	covered atomic.Int64 // the highest offset a completed fsync covers
}

func (r *syncRecorder) hook(f *os.File) error {
	size, err := contentLength(f)
	if err != nil {
		return err
	}
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	for {
		old := r.covered.Load()
		if size <= old || r.covered.CompareAndSwap(old, size) {
			return nil
		}
	}
}

// lineEnds maps each line's sequence to the offset just past its line feed,
// over the segment's content (the bytes before its first NUL).
func lineEnds(t *testing.T, path string) map[int64]int64 {
	t.Helper()
	data, err := ReadSegmentContent(path)
	if err != nil {
		t.Fatal(err)
	}
	ends := map[int64]int64{}
	var off int64
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if line[len(line)-1] != '\n' {
			t.Fatalf("torn line at offset %d: %q", off, line)
		}
		rec, err := DecodeLine(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil {
			t.Fatalf("line at offset %d: %v", off, err)
		}
		off += int64(len(line))
		ends[rec.Sequence] = off
	}
	return ends
}

// TestEmitterGroupCommitCoversEveryLineBeforeReturn: sixteen goroutines
// emit at once under SyncEveryLine. Every Emit returns only after an fsync
// that began after its bytes were written has completed (the recorder's
// covered offset is past the line's end); the segment holds every line
// whole and in sequence order; and the fsyncs are fewer than the lines,
// because callers that wrote while one fsync ran share the next.
func TestEmitterGroupCommitCoversEveryLineBeforeReturn(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine, Now: time.Now})
	rec := &syncRecorder{delay: 2 * time.Millisecond}
	e.syncHook = rec.hook

	const goroutines, perGoroutine = 16, 20
	type ret struct {
		seq     int64
		covered int64
	}
	rets := make([][]ret, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				seq, err := e.Emit(&Accept{Conn: int64(g*perGoroutine + i + 1), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"})
				if err != nil {
					t.Error(err)
					return
				}
				// What the disk held the moment this call returned.
				rets[g] = append(rets[g], ret{seq: seq, covered: rec.covered.Load()})
			}
		}(g)
	}
	wg.Wait()
	lines := int64(goroutines * perGoroutine)
	syncs := e.SyncCount()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	ends := lineEnds(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	if int64(len(ends)) != lines+1 {
		t.Fatalf("want %d lines on disk, got %d", lines+1, len(ends))
	}
	// Sequence order is file order: ends grow with the sequence.
	for seq := int64(2); seq <= lines+1; seq++ {
		if ends[seq] <= ends[seq-1] {
			t.Fatalf("sequence %d does not follow %d in the file", seq, seq-1)
		}
	}
	for g := range rets {
		if len(rets[g]) != perGoroutine {
			t.Fatalf("goroutine %d returned %d of %d emits", g, len(rets[g]), perGoroutine)
		}
		for _, r := range rets[g] {
			if r.covered < ends[r.seq] {
				t.Fatalf("Emit of sequence %d returned with %d bytes synced, its line ends at %d: the caller was told before the covering fsync completed", r.seq, r.covered, ends[r.seq])
			}
		}
	}
	if syncs >= lines {
		t.Fatalf("%d fsyncs for %d lines: no group commit", syncs, lines)
	}
	t.Logf("%d lines, %d fsyncs", lines, syncs)
}

// TestEmitterFsyncFailureFailsEveryWaiter: when the fsync that was to cover
// a batch fails, every caller whose line was in it gets the error, none is
// told its line is durable, the failure is sticky (Err), and a later Emit
// with the disk healthy again still fails.
func TestEmitterFsyncFailureFailsEveryWaiter(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine, Now: time.Now})
	boom := errors.New("fsync: input/output error")
	var gate sync.WaitGroup
	gate.Add(1)
	e.syncHook = func(f *os.File) error {
		gate.Wait() // hold the first fsync until every caller has written or queued
		return boom
	}
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.Emit(&Accept{Conn: int64(i + 1), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"})
		}(i)
	}
	// Let the callers pile up behind the held fsync, then release it.
	time.Sleep(50 * time.Millisecond)
	gate.Done()
	wg.Wait()
	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d was told its line is durable after the fsync failed", i)
		}
	}
	if !errors.Is(e.Err(), boom) {
		t.Fatalf("Err must be the fsync failure, got %v", e.Err())
	}
	e.syncHook = nil
	if _, err := e.Emit(&Accept{Conn: n + 1, Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"}); !errors.Is(err, boom) {
		t.Fatalf("a later Emit must return the sticky fsync failure, got %v", err)
	}
	if err := e.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close must report the sticky failure, got %v", err)
	}
}

// TestEmitterFsyncFailureSeam: the plain seam, one caller: the error is
// returned wrapped, and it sticks.
func TestEmitterFsyncFailureSeam(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine})
	defer e.Close()
	boom := errors.New("fsync: input/output error")
	e.failSync = boom
	if _, err := e.Emit(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"}); !errors.Is(err, boom) {
		t.Fatalf("Emit must return the fsync error, got %v", err)
	}
	e.failSync = nil
	if _, err := e.Emit(&Accept{Conn: 2, Listener: "a:1", Remote: "b:2"}); !errors.Is(err, boom) {
		t.Fatalf("after a failed fsync the emitter must stay failed, got %v", err)
	}
	if !errors.Is(e.Err(), boom) {
		t.Fatal("Err must report the sticky failure")
	}
}

// TestEmitterRotationAndCloseSyncWhatPrecedesThem: a rotation's closing
// fsync and Close's cover every byte of the segment they close, whatever
// the group commit did before them: for every segment, the highest offset
// a completed fsync covered is the segment's content length, which after
// the truncation at close is also its size.
func TestEmitterRotationAndCloseSyncWhatPrecedesThem(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine, MaxSegmentBytes: 2048})
	var mu sync.Mutex
	covered := map[string]int64{}
	e.syncHook = func(f *os.File) error {
		length, err := contentLength(f)
		if err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		mu.Lock()
		if length > covered[filepath.Base(f.Name())] {
			covered[filepath.Base(f.Name())] = length
		}
		mu.Unlock()
		return nil
	}
	for i := 0; i < 40; i++ {
		if _, err := e.Emit(&Accept{Conn: int64(i + 1), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Boots[0].Segments) < 2 {
		t.Fatalf("want a rotation, got %d segment(s)", len(tr.Boots[0].Segments))
	}
	for _, name := range tr.Boots[0].Segments {
		content := requireExactSize(t, filepath.Join(root, "0000000001", name))
		if covered[name] != int64(len(content)) {
			t.Fatalf("segment %s: %d bytes, the fsync that closed it covered %d", name, len(content), covered[name])
		}
	}
}

// TestEmitterEmitAllIsConsecutiveOneWriteOneSync: EmitAll of a handshake
// and an acl line gives them consecutive sequences in the order given,
// lands them in one write and covers them with one fsync, after which
// both are on disk in order.
func TestEmitterEmitAllIsConsecutiveOneWriteOneSync(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine})
	rec := &syncRecorder{}
	e.syncHook = rec.hook
	before := e.SyncCount()
	proto := "TLS 1.3"
	first, err := e.EmitAll(
		&Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: proto},
		&ACL{Conn: 1, Decision: "allow", Rule: "allow-all", Reason: "allowed by allow-all"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first != 2 {
		t.Fatalf("first sequence %d, want 2", first)
	}
	if got := e.SyncCount() - before; got != 1 {
		t.Fatalf("%d fsyncs for the pair, want 1", got)
	}
	path := filepath.Join(root, "0000000001", "0000000001.trace")
	ends := lineEnds(t, path)
	if ends[2] == 0 || ends[3] == 0 || ends[3] <= ends[2] {
		t.Fatalf("the pair is not on disk in order: %v", ends)
	}
	if rec.covered.Load() < ends[3] {
		t.Fatalf("EmitAll returned with %d bytes synced, the acl line ends at %d", rec.covered.Load(), ends[3])
	}
	lines := readLines(t, path)
	if len(lines) != 3 || !bytes.Contains(lines[1], []byte(`"kind":"handshake"`)) || !bytes.Contains(lines[2], []byte(`"kind":"acl"`)) {
		t.Fatalf("want start, handshake, acl; got %d lines", len(lines))
	}
	// The next line follows the pair.
	seq, err := e.Emit(&Close{Conn: 1, Reason: "eof", DurationMS: 1})
	if err != nil || seq != 4 {
		t.Fatalf("want sequence 4 after the pair, got %d (%v)", seq, err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(tr.Boots[0].Records); n != 4 {
		t.Fatalf("want 4 records, got %d", n)
	}
}

// TestEmitterEmitAllRefusesAllOnAnInvalidBody: an invalid body anywhere in
// the batch refuses the whole batch before any sequence is consumed, and
// does not fail the emitter.
func TestEmitterEmitAllRefusesAllOnAnInvalidBody(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine})
	defer e.Close()
	proto := "TLS 1.3"
	if _, err := e.EmitAll(&Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: proto}, &ACL{Conn: 1, Decision: "maybe", Rule: "r", Reason: "x"}); err == nil {
		t.Fatal("an invalid second body must refuse the batch")
	}
	if _, err := e.EmitAll(&Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: proto}, nil); err == nil {
		t.Fatal("a nil body must refuse the batch")
	}
	if _, err := e.EmitAll(); err == nil {
		t.Fatal("an empty batch must be refused")
	}
	seq, err := e.Emit(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"})
	if err != nil || seq != 2 {
		t.Fatalf("want sequence 2 after a refused batch, got %d (%v)", seq, err)
	}
	lines := readLines(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	if len(lines) != 2 {
		t.Fatalf("a refused batch must write nothing: %d lines", len(lines))
	}
}

// TestEmitterEmitAllTornTailReadsAsTwoEmitsWould: a crash in the middle of
// the pair's write leaves the handshake line whole and the acl line torn,
// exactly what a crash between two Emits leaves; the reader keeps the
// whole line and ignores the torn tail (README.md section 1.4, rule 5).
func TestEmitterEmitAllTornTailReadsAsTwoEmitsWould(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine})
	proto := "TLS 1.3"
	if _, err := e.EmitAll(&Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: proto}, &ACL{Conn: 1, Decision: "allow", Rule: "allow-all", Reason: "allowed by allow-all"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "0000000001", "0000000001.trace")
	data := segmentContent(t, path)
	lines := bytes.SplitAfter(data, []byte("\n"))
	// Tear the acl line: keep the start line, the handshake line and half
	// of the acl line.
	torn := append(append([]byte{}, lines[0]...), lines[1]...)
	torn = append(torn, lines[2][:len(lines[2])/2]...)
	if err := os.WriteFile(path, torn, 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatalf("a torn final line must be ignored: %v", err)
	}
	b := tr.Boots[0]
	if !b.Torn {
		t.Fatal("the boot must be marked torn")
	}
	if len(b.Records) != 2 || b.Records[1].Body.Kind() != KindHandshake {
		t.Fatalf("want start and handshake, got %d records", len(b.Records))
	}
}
