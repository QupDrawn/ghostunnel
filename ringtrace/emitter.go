package ringtrace

// emitter.go is the single writer of gt/. See README.md for the layout,
// the naming and the fsync policy it implements. Every segment is
// pre-extended to MaxSegmentBytes when it is opened (and that size synced)
// so that the fsync after each write commits data alone and never a size
// change; lines are written at a tracked offset into that space, and the
// segment is truncated to its written length when it is closed. A
// segment's content is its bytes before the first NUL (README.md section
// 1.3).

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// SyncPolicy says when the emitter calls fsync.
type SyncPolicy int

const (
	// SyncEveryLine fsyncs the segment after every line, so a line the
	// caller has been told about is on disk. The default.
	SyncEveryLine SyncPolicy = iota
	// SyncOnRotateAndClose fsyncs only when a segment is closed, at
	// rotation and at Close. A power loss can then lose lines the caller
	// was told were written; an operating-system crash cannot reorder them.
	SyncOnRotateAndClose
)

// DefaultMaxSegmentBytes is the segment size at which the emitter rotates.
const DefaultMaxSegmentBytes int64 = 64 << 20

// Options configures Open.
type Options struct {
	// Config is what the start line records. Required.
	Config Config
	// PID is the process id the start line records; 0 means os.Getpid().
	PID int
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// MaxSegmentBytes is the size at which a new segment is opened; 0
	// means DefaultMaxSegmentBytes.
	MaxSegmentBytes int64
	// Sync is the fsync policy.
	Sync SyncPolicy
	// CABundle is the bytes of the CA bundle that Config.Material records
	// under ca with a hash, exactly as they were hashed. Open stores them
	// in the material store (StoreMaterial, gt/material/<sha256>) under
	// the lock and before the start line that names the hash is written,
	// so a durable start line never names a bundle the store lacks. nil
	// when Config.Material hashes no bundle. Bytes that do not hash to the
	// entry, or a store that cannot be written, are a failed Open with no
	// boot created.
	CABundle []byte
}

// Emitter appends trace lines under gt/. It is safe for concurrent use;
// lines are written whole and in sequence order.
type Emitter struct {
	mu      sync.Mutex
	root    string
	bootDir string
	boot    int64
	opts    Options
	seg     *os.File
	segSize int64     // bytes written to seg: the offset the next write takes
	next    int64     // the sequence the next line takes
	lastAt  time.Time // the timestamp of the last line written
	closed  bool
	failed  error
	// enc is the buffer append encodes a batch into, reused from batch to
	// batch under mu: the write copies it into the segment before append
	// returns, so none of its bytes outlive the call. One grown beyond
	// maxEncodeBytes by a large batch is not kept.
	enc []byte
	// lock is gt/lock, held exclusively for the emitter's lifetime so no
	// second emitter opens under the same root.
	lock *os.File

	// Group commit, under SyncEveryLine. batch collects the callers whose
	// lines were written since the last fsync began; inflight is the batch
	// whose fsync is running, with the mutex released. The first caller
	// into a batch leads it: it waits for the in-flight fsync to end, then
	// fsyncs once for every line the batch holds and releases them all.
	// A rotation or Close never closes a segment while an fsync on it is
	// in flight; a failure that must close the segment while one is (fail)
	// leaves it to the leader as orphan.
	batch    *syncBatch
	inflight *syncBatch
	orphan   *os.File

	// Test seams: failWrites makes every write return that error;
	// shortWrites makes every write land one byte short.
	failWrites  error
	shortWrites bool
	// failSync makes every fsync of a segment return that error; syncHook,
	// when set, is called in place of f.Sync (a test records what each
	// fsync covered).
	failSync error
	syncHook func(f *os.File) error
	// syncs counts the fsyncs issued on segments (benchmarks report it
	// per line).
	syncs atomic.Int64
}

// SyncCount is the number of fsyncs issued on segments so far (a seam for
// tests and benchmarks that count what a path pays): one per segment
// opened (its pre-extension), one per group commit under SyncEveryLine,
// and one per segment closed (rotation or Close).
func (e *Emitter) SyncCount() int64 { return e.syncs.Load() }

// SetSyncHook installs hook in place of every sync of a segment from then
// on: the group commit's, the pre-extension's at open and the truncation's
// at close. It is a seam for tests outside the package that hold a commit
// back or fail it; an error the hook returns is that sync's failure, sticky
// like any other. A nil hook restores the platform's syncs. A commit whose
// sync has already begun keeps the hook it began with.
func (e *Emitter) SetSyncHook(hook func(f *os.File) error) {
	e.mu.Lock()
	e.syncHook = hook
	e.mu.Unlock()
}

// syncFile fsyncs a segment, through the test seams: the sync of a size
// change, at open (the pre-extension) and at close (the truncation). The
// caller holds e.mu.
func (e *Emitter) syncFile(f *os.File) error {
	return e.syncWith(f, (*os.File).Sync, e.syncHook, e.failSync)
}

// syncLines makes the lines written to a segment durable, through the
// same seams: the group commit's sync, data-only where the platform has
// one (syncdata_linux.go), the segment's size being fixed already. The
// seams see no difference between the two: failSync fails both, syncHook
// replaces both, SyncCount counts both. It runs with the mutex released,
// on the seams the leader read under it.
func (e *Emitter) syncLines(f *os.File, hook func(*os.File) error, failSync error) error {
	return e.syncWith(f, syncData, hook, failSync)
}

func (e *Emitter) syncWith(f *os.File, do func(*os.File) error, hook func(*os.File) error, failSync error) error {
	e.syncs.Add(1)
	if failSync != nil {
		return failSync
	}
	if hook != nil {
		return hook(f)
	}
	return do(f)
}

// syncBatch is one group of lines made durable by one fsync. done is closed
// once that fsync has completed (or been refused); err is its outcome,
// the same for every line in the batch.
type syncBatch struct {
	done chan struct{}
	err  error
}

var (
	reBootName    = regexp.MustCompile(`^[0-9]{10}$`)
	reSegmentName = regexp.MustCompile(`^[0-9]{10}\.trace$`)
)

// maxNumber is the largest boot or sequence number a name can carry.
const maxNumber int64 = 9999999999

// BootName is the directory name of a boot number.
func BootName(boot int64) string { return fmt.Sprintf("%010d", boot) }

// SegmentName is the file name of the segment whose first line has the
// given sequence.
func SegmentName(seq int64) string { return fmt.Sprintf("%010d.trace", seq) }

func numberOfName(name string) int64 {
	n, err := strconv.ParseInt(name[:10], 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// LockName is the one regular file under the trace root: the emitter's
// exclusive lock.
const LockName = "lock"

// DirMode and FileMode are the permission bits the emitter and the chain
// store request for everything they create under the trace root: 0750 for
// a directory (a boot, chains/), 0640 for a file (the lock, a segment, a
// chain). The trace names every peer that presented a certificate, by
// subject, serial and the chain itself, so it is readable by the root's
// owner and the root's group, which the deployment makes the readers'
// group (deploy/tree.tsv, gtring-trace), and by nobody else. The process
// umask can only narrow these, never widen them; the unit sets it to 0027
// so that exactly these land.
const (
	DirMode  os.FileMode = 0o750
	FileMode os.FileMode = 0o640
)

// listBoots returns the boot numbers under root, ascending. Anything under
// root that is not a directory named by ten digits, the regular file
// LockName or the directories ChainsDirName and MaterialDirName, is an
// error: the tree is exactly this and nothing else.
func listBoots(root string) ([]int64, error) {
	des, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var boots []int64
	for _, de := range des {
		if de.Name() == LockName && de.Type().IsRegular() {
			continue
		}
		if (de.Name() == ChainsDirName || de.Name() == MaterialDirName) && de.IsDir() {
			continue
		}
		if !de.IsDir() || !reBootName.MatchString(de.Name()) {
			return nil, &MalformedError{Path: filepath.Join(root, de.Name()), Reason: "unexpected entry under the trace root"}
		}
		boots = append(boots, numberOfName(de.Name()))
	}
	sort.Slice(boots, func(i, j int) bool { return boots[i] < boots[j] })
	return boots, nil
}

// Open starts a new boot under root: it takes the exclusive lock on
// root/lock (a second emitter under the same root fails here, before any
// boot is created), stores the CA bundle the configuration hashed
// (Options.CABundle, StoreMaterial), then takes the highest boot number
// present plus one (or 1), creates that directory, opens its first
// segment and writes the start line. Root must already exist. Any failure
// is returned and nothing is served on it. The lock is held until Close,
// or until the process dies.
func Open(root string, o Options) (*Emitter, error) {
	lock, err := takeLock(root)
	if err != nil {
		return nil, err
	}
	e, err := open(root, o, lock)
	if err != nil {
		_ = unlockFile(lock)
		lock.Close()
		return nil, err
	}
	return e, nil
}

// takeLock opens root/lock and locks it exclusively, without waiting.
func takeLock(root string) (*os.File, error) {
	path := filepath.Join(root, LockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, FileMode)
	if err != nil {
		return nil, fmt.Errorf("ringtrace: lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("ringtrace: another emitter holds the lock %s, or it cannot be taken: %w", path, err)
	}
	return f, nil
}

func open(root string, o Options, lock *os.File) (*Emitter, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.PID == 0 {
		o.PID = os.Getpid()
	}
	if o.MaxSegmentBytes <= 0 {
		o.MaxSegmentBytes = DefaultMaxSegmentBytes
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("ringtrace: root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("ringtrace: root %s is not a directory", root)
	}
	boots, err := listBoots(root)
	if err != nil {
		return nil, err
	}
	boot := int64(1)
	if len(boots) > 0 {
		boot = boots[len(boots)-1] + 1
	}
	if boot > maxNumber {
		return nil, errors.New("ringtrace: boot numbers exhausted")
	}
	start := &Start{Boot: boot, PID: int64(o.PID), Config: o.Config}
	if err := start.validate(); err != nil {
		return nil, fmt.Errorf("ringtrace: config: %v", err)
	}
	// The bundle the start line's material names by hash is stored before
	// the boot exists, so that no start line, durable or not, names a hash
	// the store lacks.
	if err := StoreMaterial(root, o.Config.Material, o.CABundle); err != nil {
		return nil, err
	}
	e := &Emitter{root: root, boot: boot, opts: o, next: 1, lock: lock}
	e.bootDir = filepath.Join(root, BootName(boot))
	if err := os.Mkdir(e.bootDir, DirMode); err != nil {
		return nil, fmt.Errorf("ringtrace: %w", err)
	}
	if err := syncDir(root); err != nil {
		return nil, fmt.Errorf("ringtrace: %w", err)
	}
	if err := e.openSegment(1); err != nil {
		return nil, err
	}
	if _, err := e.Emit(start); err != nil {
		return nil, err
	}
	return e, nil
}

// openSegment creates the segment whose first line will carry seq. The
// file must not already exist. It is pre-extended to MaxSegmentBytes and
// that size is synced (one fsync, counted in SyncCount) before any line
// is written, so the fsync after each write commits data alone and never
// a size change; the directory is then synced so the file's existence is
// as durable as its content. The file is opened without O_APPEND: an
// append would land after the pre-extension, so every write goes through
// WriteAt at segSize.
func (e *Emitter) openSegment(seq int64) error {
	path := filepath.Join(e.bootDir, SegmentName(seq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, FileMode)
	if err != nil {
		return fmt.Errorf("ringtrace: %w", err)
	}
	if err := f.Truncate(e.opts.MaxSegmentBytes); err != nil {
		f.Close()
		return fmt.Errorf("ringtrace: pre-extend: %w", err)
	}
	if err := e.syncFile(f); err != nil {
		f.Close()
		return fmt.Errorf("ringtrace: pre-extend: fsync: %w", err)
	}
	if err := syncDir(e.bootDir); err != nil {
		f.Close()
		return fmt.Errorf("ringtrace: %w", err)
	}
	e.seg = f
	e.segSize = 0
	return nil
}

// closeSegment truncates the current segment to its written length, syncs
// it and closes it. After it a segment holds exactly its lines and no
// unwritten tail.
func (e *Emitter) closeSegment() error {
	if e.seg == nil {
		return nil
	}
	f := e.seg
	e.seg = nil
	if err := f.Truncate(e.segSize); err != nil {
		f.Close()
		return fmt.Errorf("ringtrace: truncate: %w", err)
	}
	if err := e.syncFile(f); err != nil {
		f.Close()
		return fmt.Errorf("ringtrace: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("ringtrace: %w", err)
	}
	return nil
}

// Boot returns this process's boot number.
func (e *Emitter) Boot() int64 { return e.boot }

// Root returns the trace root this emitter writes under, where the chain
// store (WriteChain) lives beside the boot directories.
func (e *Emitter) Root() string { return e.root }

// Err returns the sticky failure, if any. Once a write has failed the
// emitter cannot know what reached the disk, so every later Emit fails too;
// the process restarts into a new boot.
func (e *Emitter) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.failed
}

// Emit appends one line and returns the sequence it was given. An invalid
// body is refused before any sequence is consumed and does not fail the
// emitter; a write that does not land whole fails the emitter for good.
// Under SyncEveryLine, Emit returns only once an fsync that began after
// the line was written has completed; lines written while an fsync runs
// share the next one (group commit), so a caller is never told its line
// is durable before it is.
func (e *Emitter) Emit(b Body) (int64, error) {
	return e.EmitAll(b)
}

// EmitAll appends the bodies as consecutive lines, in the order given, in
// one write, and returns the first sequence. All the bodies are validated
// before any sequence is consumed, so an invalid one refuses them all.
// Under SyncEveryLine the lines are covered by one fsync, all or nothing:
// EmitAll returns only once it has completed, and a failure fails the
// emitter for good. A crash mid-write leaves at most one torn final line,
// exactly as a crash between two Emits would (README.md section 2).
func (e *Emitter) EmitAll(bodies ...Body) (int64, error) {
	first, wait, err := e.emitAll(bodies, false)
	if err != nil {
		return 0, err
	}
	if err := wait(); err != nil {
		return 0, err
	}
	return first, nil
}

// EmitAllAsync is EmitAll up to and including the write: when it returns
// with a nil error the lines are written and sequenced, in one write, in
// the order given, and they are durable once the returned wait returns
// nil. It differs from EmitAll only in who waits: under SyncEveryLine, if
// the caller leads the batch its lines joined, the commit runs on a new
// goroutine instead of the caller's, and the caller does whatever it has
// to do meanwhile (ghostunnel dials the backend) before calling wait,
// which blocks on the batch's commit and returns its outcome. Every line
// written before wait returns is covered by the commit wait waits on, as
// with EmitAll, and a failure fails the emitter for good, reported by wait
// and by every later call. Rotation and Close are unchanged: neither closes
// a segment under a running commit, whichever goroutine runs it. Under
// SyncOnRotateAndClose there is nothing to wait for and wait returns nil
// at once. An error from EmitAllAsync itself (an invalid body, a write that
// failed) comes with a nil wait; a failure is reported once, never through
// both.
func (e *Emitter) EmitAllAsync(bodies ...Body) (first int64, wait func() error, err error) {
	return e.emitAll(bodies, true)
}

// emitAll is the body of EmitAll and EmitAllAsync: the write under the
// mutex through append, then the group commit's wait. With async false the
// caller that leads its batch runs the commit itself before wait is
// returned, so wait returns the outcome at once; with async true the
// commit runs on its own goroutine and wait blocks until it is done.
func (e *Emitter) emitAll(bodies []Body, async bool) (first int64, wait func() error, err error) {
	if len(bodies) == 0 {
		return 0, nil, errors.New("ringtrace: no bodies")
	}
	e.mu.Lock()
	first, b, leader, prev, err := e.append(bodies)
	e.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	if b == nil {
		// SyncOnRotateAndClose: nothing to wait for.
		return first, func() error { return nil }, nil
	}
	if leader {
		if async {
			go e.commit(b, prev)
		} else {
			e.commit(b, prev)
		}
	}
	return first, func() error {
		<-b.done
		return b.err
	}, nil
}

// append validates, encodes and writes the bodies as consecutive lines
// under the mutex, rotating first if the segment is full. It returns the
// first sequence and, under SyncEveryLine, the batch the caller waits on,
// whether the caller leads it, and the batch whose fsync was in flight
// when the caller's batch was formed (which the leader waits for first).
// The caller holds e.mu.
func (e *Emitter) append(bodies []Body) (first int64, b *syncBatch, leader bool, prev *syncBatch, err error) {
	for {
		if e.failed != nil {
			return 0, nil, false, nil, e.failed
		}
		if e.closed {
			return 0, nil, false, nil, errors.New("ringtrace: emitter is closed")
		}
		for _, body := range bodies {
			if body == nil {
				return 0, nil, false, nil, errors.New("ringtrace: nil body")
			}
		}
		if e.next+int64(len(bodies))-1 > maxNumber {
			return 0, nil, false, nil, e.fail(errors.New("ringtrace: sequence numbers exhausted"))
		}
		now := e.opts.Now().UTC().Truncate(time.Second)
		if now.Before(e.lastAt) {
			// A clock that runs backwards is a clock that cannot be read.
			return 0, nil, false, nil, e.fail(fmt.Errorf("ringtrace: clock went back from %s to %s", formatTimestamp(e.lastAt), formatTimestamp(now)))
		}
		// The batch is encoded into the emitter's one encode buffer, at
		// least sized for its lines: a line that does not fit grows it,
		// and the bytes are those EncodeLine would give line by line.
		// Every line of the batch carries now, formatted once.
		if cap(e.enc) < lineSizeHint*len(bodies) {
			e.enc = make([]byte, 0, lineSizeHint*len(bodies))
		}
		var ts [len(timestampLayout)]byte
		at := now.AppendFormat(ts[:0], timestampLayout)
		buf := e.enc[:0]
		for i, body := range bodies {
			var err error
			buf, err = appendLine(buf, Record{Sequence: e.next + int64(i), At: now, Body: body}, at)
			if err != nil {
				e.keepEncode(buf)
				return 0, nil, false, nil, err
			}
		}
		e.keepEncode(buf)
		if e.segSize > 0 && e.segSize+int64(len(buf)) > e.opts.MaxSegmentBytes {
			if in := e.inflight; in != nil {
				// The segment cannot be closed under a running fsync. Wait
				// for it outside the lock and start over: the sequence,
				// the clock and the state may all have moved.
				e.mu.Unlock()
				<-in.done
				e.mu.Lock()
				continue
			}
			if err := e.closeSegment(); err != nil {
				return 0, nil, false, nil, e.fail(err)
			}
			if err := e.openSegment(e.next); err != nil {
				return 0, nil, false, nil, e.fail(err)
			}
		}
		n, err := e.write(buf)
		if err != nil {
			return 0, nil, false, nil, e.fail(fmt.Errorf("ringtrace: write: %w", err))
		}
		if n != len(buf) {
			return 0, nil, false, nil, e.fail(fmt.Errorf("ringtrace: short write: %d of %d bytes", n, len(buf)))
		}
		e.segSize += int64(n)
		first = e.next
		e.next += int64(len(bodies))
		e.lastAt = now
		if e.opts.Sync != SyncEveryLine {
			return first, nil, false, nil, nil
		}
		if e.batch == nil {
			e.batch = &syncBatch{done: make(chan struct{})}
			leader = true
		}
		return first, e.batch, leader, e.inflight, nil
	}
}

// maxEncodeBytes is the largest encode buffer the emitter keeps for the
// next batch.
const maxEncodeBytes = 64 << 10

// keepEncode keeps buf as the encode buffer for the next batch, unless a
// large batch grew it past maxEncodeBytes. The caller holds e.mu.
func (e *Emitter) keepEncode(buf []byte) {
	if cap(buf) > maxEncodeBytes {
		e.enc = nil
		return
	}
	e.enc = buf[:0]
}

// commit is the leader's half of the group commit: once the fsync that
// was in flight when its batch formed has ended, it takes the batch (every
// line written since that fsync began is in it), fsyncs the segment with
// the mutex released, records a failure as sticky, and releases every
// caller in the batch with the one outcome. The segment is the one open
// when the batch is taken: lines the batch holds in a segment a rotation
// closed meanwhile were synced by that rotation, and lines written before
// Close were synced by Close. It runs on the leader's goroutine under
// EmitAll and on a goroutine of its own under EmitAllAsync; nothing here
// depends on which, every read and write of the emitter's state is under
// the mutex, and Close and rotation wait on inflight, which is set here,
// not on the caller.
func (e *Emitter) commit(b *syncBatch, prev *syncBatch) {
	if prev != nil {
		<-prev.done
	}
	e.mu.Lock()
	e.batch = nil
	e.inflight = b
	f, failed := e.seg, e.failed
	hook, failSync := e.syncHook, e.failSync
	e.mu.Unlock()

	var err error
	switch {
	case failed != nil:
		err = failed
	case f == nil:
		// Closed under a healthy emitter: closeSegment synced the lines.
	default:
		if err = e.syncLines(f, hook, failSync); err != nil {
			err = fmt.Errorf("ringtrace: fsync: %w", err)
		}
	}

	e.mu.Lock()
	e.inflight = nil
	if err != nil {
		if e.failed == nil {
			err = e.fail(err)
		} else {
			err = e.failed
		}
	}
	if e.orphan != nil {
		// The failure path's close, deferred to here: the truncation to
		// the written length is best effort, the emitter has failed.
		_ = e.orphan.Truncate(e.segSize)
		e.orphan.Close()
		e.orphan = nil
	}
	e.mu.Unlock()
	b.err = err
	close(b.done)
}

// write lands line at the tracked offset segSize, inside the pre-extended
// segment (or past its end, for a first group larger than the segment).
func (e *Emitter) write(line []byte) (int, error) {
	if e.failWrites != nil {
		return 0, e.failWrites
	}
	if e.shortWrites {
		n, err := e.seg.WriteAt(line[:len(line)-1], e.segSize)
		if err != nil {
			return n, err
		}
		return n, io.ErrShortWrite
	}
	return e.seg.WriteAt(line, e.segSize)
}

// fail records the sticky failure and closes the segment, unless an fsync
// on it is in flight, in which case the leader closes it once done. The
// truncation to the written length is best effort: the emitter has
// failed, and a segment left pre-extended reads the same (README.md
// section 1.3). The caller holds e.mu.
func (e *Emitter) fail(err error) error {
	e.failed = err
	if e.seg != nil {
		if e.inflight != nil {
			e.orphan = e.seg
		} else {
			_ = e.seg.Truncate(e.segSize)
			e.seg.Close()
		}
		e.seg = nil
	}
	return err
}

// Close syncs and closes the current segment and releases the lock. Emit
// fails afterwards. An fsync in flight is waited for first, so the segment
// is never closed under one.
func (e *Emitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	for e.inflight != nil {
		in := e.inflight
		e.mu.Unlock()
		<-in.done
		e.mu.Lock()
	}
	defer e.releaseLock()
	if e.failed != nil {
		return e.failed
	}
	return e.closeSegment()
}

func (e *Emitter) releaseLock() {
	if e.lock == nil {
		return
	}
	_ = unlockFile(e.lock)
	e.lock.Close()
	e.lock = nil
}

// syncDir fsyncs a directory so a created entry is durable. Windows has no
// directory fsync; there the call is a no-op, which the README records.
// The directory is opened by openDir, which refuses anything else at the
// name without waiting on it.
func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := openDir(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
