package ringtrace

// The tests of EmitAllAsync: the write is done when it returns, the commit
// runs meanwhile, wait returns the commit's outcome, and everything else
// (who a later caller's line is covered by, Close, the sticky failure) is
// as it is under EmitAll. They go through the same seams as the
// group-commit tests.

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// heldSync is a syncHook that reports when it is entered and blocks until
// released, then syncs for real. Later calls pass straight through.
type heldSync struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newHeldSync() *heldSync {
	return &heldSync{entered: make(chan struct{}, 1), release: make(chan struct{})}
}

func (h *heldSync) hook(f *os.File) error {
	h.once.Do(func() {
		h.entered <- struct{}{}
		<-h.release
	})
	return f.Sync()
}

// awaitEntered fails the test unless the hook was entered within the wait.
func (h *heldSync) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the commit's sync never began")
	}
}

// returnsWithin reports whether fn returned within d.
func returnsWithin(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestEmitterEmitAllAsyncReturnsBeforeTheSync: EmitAllAsync returns while
// the commit's sync is still blocked in the hook, with the lines written
// and sequenced; wait blocks until the sync completes and then returns nil;
// the pair paid one sync and is on disk in order.
func TestEmitterEmitAllAsyncReturnsBeforeTheSync(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine})
	held := newHeldSync()
	e.syncHook = held.hook
	before := e.SyncCount()
	proto := "TLS 1.3"
	first, wait, err := e.EmitAllAsync(
		&Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: proto},
		&ACL{Conn: 1, Decision: "allow", Rule: "allow-all", Reason: "allowed by allow-all"},
	)
	if err != nil {
		t.Fatal(err)
	}
	// The call has returned; the sync it started has been entered and is
	// still held: the return did not wait for it.
	held.awaitEntered(t)
	if first != 2 {
		t.Fatalf("first sequence %d, want 2", first)
	}
	path := filepath.Join(root, "0000000001", "0000000001.trace")
	ends := lineEnds(t, path)
	if ends[2] == 0 || ends[3] == 0 || ends[3] <= ends[2] {
		t.Fatalf("the pair must be written and sequenced when EmitAllAsync returns: %v", ends)
	}
	var waitErr error
	waited := make(chan struct{})
	go func() {
		waitErr = wait()
		close(waited)
	}()
	select {
	case <-waited:
		t.Fatal("wait returned while the sync was still held")
	case <-time.After(100 * time.Millisecond):
	}
	close(held.release)
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not return once the sync was released")
	}
	if waitErr != nil {
		t.Fatalf("wait: %v", waitErr)
	}
	if got := e.SyncCount() - before; got != 1 {
		t.Fatalf("%d syncs for the pair, want 1", got)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(tr.Boots[0].Records); n != 3 {
		t.Fatalf("want start, handshake, acl; got %d records", n)
	}
}

// TestEmitterEmitAllAsyncFailureIsReturnedByWait: a failing sync is not
// seen by EmitAllAsync, which returns with the lines written, but by wait,
// which returns it wrapped; the emitter is then failed for good, exactly
// as after a failed EmitAll (Err, a later Emit, Close all report it).
func TestEmitterEmitAllAsyncFailureIsReturnedByWait(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine})
	boom := errors.New("fsync: input/output error")
	e.failSync = boom
	_, wait, err := e.EmitAllAsync(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"})
	if err != nil {
		t.Fatalf("the write succeeds; only the sync fails: %v", err)
	}
	if err := wait(); !errors.Is(err, boom) {
		t.Fatalf("wait must return the sync failure, got %v", err)
	}
	if err := wait(); !errors.Is(err, boom) {
		t.Fatalf("a second wait returns the same outcome, got %v", err)
	}
	if !errors.Is(e.Err(), boom) {
		t.Fatalf("Err must be the sync failure, got %v", e.Err())
	}
	e.failSync = nil
	if _, err := e.Emit(&Accept{Conn: 2, Listener: "a:1", Remote: "b:2"}); !errors.Is(err, boom) {
		t.Fatalf("a later Emit must return the sticky failure, got %v", err)
	}
	if _, wait, err := e.EmitAllAsync(&Accept{Conn: 3, Listener: "a:1", Remote: "b:2"}); !errors.Is(err, boom) || wait != nil {
		t.Fatalf("a later EmitAllAsync must refuse at once with the sticky failure and no wait, got %v, wait set: %t", err, wait != nil)
	}
	if err := e.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close must report the sticky failure, got %v", err)
	}
}

// TestEmitterEmitAllJoinsTheBatchBehindAnAsyncLeader: while an async
// leader's commit is held in the hook, sixteen callers Emit from other
// goroutines. Each returns only after a completed sync that covers its
// line (the recorder's covered offset is past the line's end), the leader's
// wait returns nil with its own lines covered, the segment holds every line
// in sequence order, and the syncs are fewer than the lines: the callers
// shared the commit behind the async one, as they share one behind an
// EmitAll leader.
func TestEmitterEmitAllJoinsTheBatchBehindAnAsyncLeader(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine, Now: time.Now})
	rec := &syncRecorder{delay: 2 * time.Millisecond}
	held := newHeldSync()
	e.syncHook = func(f *os.File) error {
		held.once.Do(func() {
			held.entered <- struct{}{}
			<-held.release
		})
		return rec.hook(f)
	}
	proto := "TLS 1.3"
	first, wait, err := e.EmitAllAsync(
		&Handshake{Conn: 1, Outcome: "ok", Verified: true, Protocol: proto},
		&ACL{Conn: 1, Decision: "allow", Rule: "allow-all", Reason: "allowed by allow-all"},
	)
	if err != nil {
		t.Fatal(err)
	}
	held.awaitEntered(t)

	const n = 16
	type ret struct {
		seq     int64
		covered int64
	}
	rets := make([]ret, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seq, err := e.Emit(&Accept{Conn: int64(i + 2), Listener: "0.0.0.0:8443", Remote: "10.0.0.1:1"})
			if err != nil {
				t.Error(err)
				return
			}
			rets[i] = ret{seq: seq, covered: rec.covered.Load()}
		}(i)
	}
	// Let the callers write and queue behind the held commit, then release.
	time.Sleep(50 * time.Millisecond)
	if rec.covered.Load() != 0 {
		t.Fatal("no sync may complete while the leader's is held")
	}
	close(held.release)
	wg.Wait()
	if err := wait(); err != nil {
		t.Fatalf("the leader's wait: %v", err)
	}
	leaderCovered := rec.covered.Load()
	syncs := e.SyncCount()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "0000000001", "0000000001.trace")
	ends := lineEnds(t, path)
	if int64(len(ends)) != n+3 {
		t.Fatalf("want %d lines on disk, got %d", n+3, len(ends))
	}
	for seq := int64(2); seq <= n+3; seq++ {
		if ends[seq] <= ends[seq-1] {
			t.Fatalf("sequence %d does not follow %d in the file", seq, seq-1)
		}
	}
	if leaderCovered < ends[first+1] {
		t.Fatalf("the leader's wait returned with %d bytes synced, its acl line ends at %d", leaderCovered, ends[first+1])
	}
	for i, r := range rets {
		if r.seq == 0 {
			t.Fatalf("caller %d did not return a sequence", i)
		}
		if r.covered < ends[r.seq] {
			t.Fatalf("Emit of sequence %d returned with %d bytes synced, its line ends at %d: the caller was told before the covering sync completed", r.seq, r.covered, ends[r.seq])
		}
	}
	if syncs >= n+2 {
		t.Fatalf("%d syncs for %d lines: the callers did not share a commit", syncs, n+2)
	}
	t.Logf("%d lines, %d syncs", n+2, syncs)
}

// TestEmitterCloseWaitsForAnAsyncCommit: Close called while an async
// commit is held in the hook does not return until that commit has ended,
// so the segment is never closed under a running sync; afterwards the
// segment is exact, holds every line, wait returns nil, and a later emit
// is refused as closed.
func TestEmitterCloseWaitsForAnAsyncCommit(t *testing.T) {
	root := t.TempDir()
	e := openTestEmitter(t, root, Options{Sync: SyncEveryLine})
	held := newHeldSync()
	e.syncHook = held.hook
	_, wait, err := e.EmitAllAsync(&Accept{Conn: 1, Listener: "a:1", Remote: "b:2"}, &Close{Conn: 1, Reason: "halt", DurationMS: 0})
	if err != nil {
		t.Fatal(err)
	}
	held.awaitEntered(t)
	var closeErr error
	closed := make(chan struct{})
	go func() {
		closeErr = e.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while the commit's sync was still held")
	case <-time.After(100 * time.Millisecond):
	}
	close(held.release)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return once the commit ended")
	}
	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	if err := wait(); err != nil {
		t.Fatalf("wait after Close: %v", err)
	}
	if _, err := e.Emit(&Accept{Conn: 2, Listener: "a:1", Remote: "b:2"}); err == nil {
		t.Fatal("Emit after Close must be refused")
	}
	content := requireExactSize(t, filepath.Join(root, "0000000001", "0000000001.trace"))
	if len(content) == 0 {
		t.Fatal("the closed segment is empty")
	}
	tr, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(tr.Boots[0].Records); n != 3 {
		t.Fatalf("want start, accept, close; got %d records", n)
	}
	if !returnsWithin(time.Second, func() { _ = e.Close() }) {
		t.Fatal("a second Close must return at once")
	}
}
