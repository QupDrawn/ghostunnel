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

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"syscall"
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

type rdcWatcher struct {
	s   *GateState
	h   syscall.Handle
	ev  syscall.Handle
	ov  syscall.Overlapped
	buf []byte
	// mu serialises the completion's handling and the next issue between
	// the goroutine and the polls.
	mu      sync.Mutex
	pending bool
	closed  bool
	done    chan struct{}
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
	w := &rdcWatcher{s: s, h: h, ev: syscall.Handle(r), buf: make([]byte, 64*1024), done: make(chan struct{})}
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
		w.s.overflow()
	case errors.Is(err, syscall.ERROR_OPERATION_ABORTED):
		// The read was cancelled under us (the thread that issued it is
		// gone): whatever happened meanwhile is unknown, so the state is
		// stale and the read is reissued.
		w.s.overflow()
	case err != nil:
		w.s.watchFailed(fmt.Errorf("GetOverlappedResult: %w", err))
		return false
	default:
		w.s.event(countNotifications(w.buf[:n]))
	}
	if err := w.issue(); err != nil {
		w.s.watchFailed(fmt.Errorf("ReadDirectoryChangesW: %w", err))
		return false
	}
	return true
}

// countNotifications walks a FILE_NOTIFY_INFORMATION chain.
func countNotifications(b []byte) int {
	n := 0
	for off := 0; off+12 <= len(b); {
		n++
		next := int(binary.LittleEndian.Uint32(b[off : off+4]))
		if next == 0 {
			break
		}
		off += next
	}
	if n == 0 {
		n = 1
	}
	return n
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
