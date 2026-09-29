//go:build windows

package ringtrace

// watch_windows.go: the store tree watched through ReadDirectoryChangesW
// on the tree root with the subtree flag, so every directory the gate
// reads is covered by one handle. One overlapped read is always pending;
// its completion signals a manual-reset event. A goroutine waits on that
// event for changes arriving between checks, and every check tests it
// without waiting, so a change the kernel has reported before the check
// began is seen by it. A completion with no bytes is the kernel saying its
// buffer overflowed: reported as such, the scan that follows sees what was
// missed.
//
// The subtree holds more than the gate reads: the trace root gt/ when it
// sits under the stores, every store's copies, and the heartbeat/ of every
// store but the coordinator's. A notification is reported unless its path
// is one the gate provably never reads (notifyFilter); everything else, a
// name it does not recognise included, is reported.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	procCreateEventW        = modkernel32.NewProc("CreateEventW")
	procResetEvent          = modkernel32.NewProc("ResetEvent")
	procGetOverlappedResult = modkernel32.NewProc("GetOverlappedResult")
)

const (
	rdcFilter = syscall.FILE_NOTIFY_CHANGE_FILE_NAME | syscall.FILE_NOTIFY_CHANGE_DIR_NAME |
		syscall.FILE_NOTIFY_CHANGE_ATTRIBUTES | syscall.FILE_NOTIFY_CHANGE_SIZE |
		syscall.FILE_NOTIFY_CHANGE_LAST_WRITE | syscall.FILE_NOTIFY_CHANGE_CREATION |
		fileNotifyChangeSecurity
	fileNotifyChangeSecurity = 0x100
	errorIOIncomplete        = syscall.Errno(996)
	errorNotifyEnumDir       = syscall.Errno(1022)
)

// rdcBufferBytes is the size of the buffer the kernel reports changes
// into; a batch that does not fit is reported as an overflow. A variable
// for the test that makes every notification overflow it.
var rdcBufferBytes = 64 * 1024

type rdcWatcher struct {
	s      *GateState
	filter *notifyFilter
	h      syscall.Handle
	ev     syscall.Handle
	ov     syscall.Overlapped
	buf    []byte
	// mu serialises the completion's handling and the next issue between
	// the goroutine and the polls.
	mu      sync.Mutex
	pending bool
	closed  bool
	done    chan struct{}
	// ignored counts the notifications the filter did not count (a seam
	// for tests that wait on it).
	ignored atomic.Int64
}

func startWatcher(root string, dirs []string, s *GateState) (treeWatcher, error) {
	name, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(name, syscall.FILE_LIST_DIRECTORY,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s for change notification: %w", root, err)
	}
	r, _, e := procCreateEventW.Call(0, 1, 0, 0)
	if r == 0 {
		_ = syscall.CloseHandle(h)
		return nil, fmt.Errorf("CreateEventW: %w", e)
	}
	w := &rdcWatcher{s: s, filter: newNotifyFilter(root, s.Gate), h: h, ev: syscall.Handle(r), buf: make([]byte, rdcBufferBytes), done: make(chan struct{})}
	w.ov.HEvent = w.ev
	if err := w.issue(); err != nil {
		_ = syscall.CloseHandle(w.ev)
		_ = syscall.CloseHandle(h)
		return nil, fmt.Errorf("ReadDirectoryChangesW %s: %w", root, err)
	}
	go w.run()
	return w, nil
}

// issue starts the next overlapped read. The caller holds w.mu.
func (w *rdcWatcher) issue() error {
	_, _, _ = procResetEvent.Call(uintptr(w.ev))
	err := syscall.ReadDirectoryChanges(w.h, &w.buf[0], uint32(len(w.buf)), true, rdcFilter, nil, &w.ov, 0)
	if err != nil {
		return err
	}
	w.pending = true
	return nil
}

// run waits for completions arriving while nobody checks, until close.
func (w *rdcWatcher) run() {
	defer close(w.done)
	for {
		r, err := syscall.WaitForSingleObject(w.ev, syscall.INFINITE)
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			return
		}
		if err != nil || r != syscall.WAIT_OBJECT_0 {
			w.mu.Unlock()
			w.s.watchFailed(fmt.Errorf("WaitForSingleObject: %v (%d)", err, r))
			return
		}
		ok := w.consumeLocked()
		w.mu.Unlock()
		if !ok {
			return
		}
	}
}

// poll tests the event without waiting and handles a completion.
func (w *rdcWatcher) poll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.pending {
		return
	}
	r, err := syscall.WaitForSingleObject(w.ev, 0)
	if err == nil && r == syscall.WAIT_OBJECT_0 {
		w.consumeLocked()
	}
}

// consumeLocked collects a completed read, reports it and issues the next.
// It returns false once the watcher has failed. The caller holds w.mu.
func (w *rdcWatcher) consumeLocked() bool {
	if !w.pending {
		return true
	}
	var n uint32
	err := getOverlappedResult(w.h, &w.ov, &n, false)
	if errors.Is(err, errorIOIncomplete) {
		return true
	}
	w.pending = false
	switch {
	case err == nil && n == 0, errors.Is(err, errorNotifyEnumDir):
		w.filter.recheckAll()
		w.s.overflow()
	case errors.Is(err, syscall.ERROR_OPERATION_ABORTED):
		// The read was cancelled under us (the thread that issued it is
		// gone): whatever happened meanwhile is unknown, so the state is
		// stale and the read is reissued.
		w.filter.recheckAll()
		w.s.overflow()
	case err != nil:
		w.s.watchFailed(fmt.Errorf("GetOverlappedResult: %w", err))
		return false
	default:
		c, ignored := countNotifications(w.buf[:n], w.filter)
		w.ignored.Add(int64(ignored))
		if c > 0 {
			w.s.event(c)
		}
	}
	if err := w.issue(); err != nil {
		w.s.watchFailed(fmt.Errorf("ReadDirectoryChangesW: %w", err))
		return false
	}
	return true
}

// countNotifications walks a FILE_NOTIFY_INFORMATION chain and returns how
// many of its notifications the filter counts and how many it does not. An
// entry whose name runs past the buffer is counted and ends the walk, and a
// buffer holding no whole entry counts once: what cannot be read is a
// change.
func countNotifications(b []byte, f *notifyFilter) (n, ignored int) {
	entries := 0
	for off := 0; off+12 <= len(b); {
		entries++
		next := int(binary.LittleEndian.Uint32(b[off : off+4]))
		size := int(binary.LittleEndian.Uint32(b[off+8 : off+12]))
		if size%2 != 0 || off+12+size > len(b) {
			n++
			break
		}
		name := make([]uint16, size/2)
		for i := range name {
			name[i] = binary.LittleEndian.Uint16(b[off+12+2*i:])
		}
		if f.counts(string(utf16.Decode(name))) {
			n++
		} else {
			ignored++
		}
		if next == 0 {
			break
		}
		off += next
	}
	if entries == 0 {
		n = 1
	}
	return n, ignored
}

// notifyFilter tells a notification of a change the gate may read from one
// of a change it never reads.
//
// Gate.Check reads, under the root, <m>\halt, <m>\fault and <m>\halts\ for
// every member m, and the coordinator's heartbeat\ and the newest file in
// it. Three kinds of path are not counted, each strictly below an entry of
// the root or of a store, so a change to an entry on the way to a read is
// never dropped:
//   - anything under gt\ (the trace root, when it is under the stores);
//   - anything under <m>\copy*\ for a member m;
//   - anything under <m>\heartbeat\ for a member m that is not the
//     coordinator.
//
// Names are matched without regard to case, as the filesystem opens them.
// A component that is not plain ASCII, or carries a '~' (an 8.3 short name
// such as HEARTB~1, which the kernel may report in place of the long one),
// matches nothing, so its path is counted.
//
// The kernel reports a change by where it happened, while the gate reads
// through links: a store, a halts\ or the coordinator's heartbeat\ that is
// a reparse point (a symbolic link, a junction) may lead into a subtree
// that is not counted. The filter is therefore on only while each of those
// directories is a plain directory: checked when the watch starts, again
// for the directory a notification names as the entry that changed (and
// for all of them when it names one that cannot be told apart, or when
// the kernel's buffer overflowed), before the notifications after it are
// judged. Once one is not, every notification counts until the watch is
// started again. The same holds, from the start, when a member or the
// coordinator is not one plain name.
type notifyFilter struct {
	on          bool
	root        string
	members     []string
	coordinator string
	gtIsMember  bool
}

func newNotifyFilter(root string, g *Gate) *notifyFilter {
	f := &notifyFilter{}
	if g == nil || !plainName(g.Coordinator) {
		return f
	}
	for _, m := range g.Members {
		if !plainName(m) {
			return f
		}
		if strings.EqualFold(m, "gt") {
			f.gtIsMember = true
		}
	}
	f.root, f.members, f.coordinator = root, append([]string(nil), g.Members...), g.Coordinator
	f.on = true
	f.recheckAll()
	return f
}

// counts reports whether a change at rel, a path relative to the root as
// the kernel reports it, may be to something Gate.Check reads.
func (f *notifyFilter) counts(rel string) bool {
	if !f.on {
		return true
	}
	first, rest, deeper := strings.Cut(rel, `\`)
	if !plainName(first) {
		f.recheckAll()
		return true
	}
	if strings.EqualFold(first, "gt") && !f.gtIsMember {
		return !deeper
	}
	if !f.isMember(first) {
		return true
	}
	if !deeper {
		f.recheck(first)
		return true
	}
	second, _, deeper := strings.Cut(rest, `\`)
	if !plainName(second) {
		f.recheckAll()
		return true
	}
	coordinator := strings.EqualFold(first, f.coordinator)
	if strings.EqualFold(second, "halts") || coordinator && strings.EqualFold(second, "heartbeat") {
		if !deeper {
			f.recheck(first + `\` + second)
		}
		return true
	}
	if !deeper {
		return true
	}
	if len(second) >= 4 && strings.EqualFold(second[:4], "copy") {
		return false
	}
	if !coordinator && strings.EqualFold(second, "heartbeat") {
		return false
	}
	return true
}

func (f *notifyFilter) isMember(name string) bool {
	for _, m := range f.members {
		if strings.EqualFold(name, m) {
			return true
		}
	}
	return false
}

// recheck turns the filter off unless the directory at rel under the root
// is a plain directory.
func (f *notifyFilter) recheck(rel string) {
	if f.on && !plainDir(filepath.Join(f.root, rel)) {
		f.on = false
	}
}

// recheckAll is recheck on every directory the gate reads through: each
// store, each store's halts\, and the coordinator's heartbeat\.
func (f *notifyFilter) recheckAll() {
	for _, m := range f.members {
		f.recheck(m)
		f.recheck(m + `\halts`)
	}
	f.recheck(f.coordinator + `\heartbeat`)
}

// plainDir reports whether path is a directory and not a reparse point.
func plainDir(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return false
	}
	a, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && a.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

// plainName is a single path component the filter can match: not empty,
// not . or .., printable ASCII with no separator, drive or stream colon,
// wildcard or '~'.
func plainName(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`\/:*?"<>|~`, c) >= 0 {
			return false
		}
	}
	return true
}

func getOverlappedResult(h syscall.Handle, ov *syscall.Overlapped, n *uint32, wait bool) error {
	var b uintptr
	if wait {
		b = 1
	}
	r, _, e := procGetOverlappedResult.Call(uintptr(h), uintptr(unsafe.Pointer(ov)), uintptr(unsafe.Pointer(n)), b)
	if r == 0 {
		return e
	}
	return nil
}

func (w *rdcWatcher) close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	if w.pending {
		_ = syscall.CancelIoEx(w.h, &w.ov)
	}
	w.mu.Unlock()
	<-w.done
	_ = syscall.CloseHandle(w.h)
	_ = syscall.CloseHandle(w.ev)
}
