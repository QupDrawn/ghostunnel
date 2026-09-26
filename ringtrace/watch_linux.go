//go:build linux

package ringtrace

// watch_linux.go: the store tree watched through inotify. One descriptor,
// one watch on each directory the gate reads. The descriptor is
// non-blocking: a goroutine reads it through the runtime's poller for
// events arriving between checks, and every check drains it first with a
// raw read, so an event queued before the check began is seen by it.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

// inotifyMask is every event that can change what the gate reads: a name
// created, removed or moved in or out, a write closed, attributes changed,
// and the watched directory itself removed or moved.
const inotifyMask = syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MOVED_TO | syscall.IN_MOVED_FROM |
	syscall.IN_CLOSE_WRITE | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

// inotifyLost is any event after which the watch no longer covers what it
// did: the directory is gone, moved, unmounted, or the watch was removed.
const inotifyLost = syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF | syscall.IN_UNMOUNT | syscall.IN_IGNORED

type inotifyWatcher struct {
	s  *GateState
	f  *os.File
	fd int
	// mu guards fd against close while a poll reads it.
	mu     sync.RWMutex
	closed bool
	done   chan struct{}
}

func startWatcher(root string, dirs []string, s *GateState) (treeWatcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	for _, d := range dirs {
		if _, err := syscall.InotifyAddWatch(fd, d, inotifyMask); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("inotify_add_watch %s: %w", d, err)
		}
	}
	w := &inotifyWatcher{s: s, fd: fd, done: make(chan struct{})}
	// A non-blocking descriptor is registered with the runtime poller by
	// NewFile, so Read below parks the goroutine and Close wakes it.
	w.f = os.NewFile(uintptr(fd), "inotify")
	go w.run()
	return w, nil
}

// run reads events arriving while nobody checks, until close.
func (w *inotifyWatcher) run() {
	defer close(w.done)
	buf := make([]byte, 64*1024)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			w.mu.RLock()
			closed := w.closed
			w.mu.RUnlock()
			if !closed {
				w.s.watchFailed(fmt.Errorf("inotify read: %w", err))
			}
			return
		}
		w.deliver(buf[:n])
	}
}

// poll drains what the kernel has ready, without blocking.
func (w *inotifyWatcher) poll() {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return
	}
	var buf [8192]byte
	for {
		n, err := syscall.Read(w.fd, buf[:])
		if n > 0 {
			w.deliver(buf[:n])
			continue
		}
		if err == nil || errors.Is(err, syscall.EAGAIN) {
			return
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		w.s.watchFailed(fmt.Errorf("inotify read: %w", err))
		return
	}
}

// deliver reports a buffer of inotify events to the state.
func (w *inotifyWatcher) deliver(b []byte) {
	n, overflow, lost := 0, false, false
	for len(b) >= syscall.SizeofInotifyEvent {
		mask := binary.NativeEndian.Uint32(b[4:8])
		size := syscall.SizeofInotifyEvent + int(binary.NativeEndian.Uint32(b[12:16]))
		if size > len(b) {
			break
		}
		n++
		if mask&syscall.IN_Q_OVERFLOW != 0 {
			overflow = true
		}
		if mask&inotifyLost != 0 {
			lost = true
		}
		b = b[size:]
	}
	if n > 0 {
		w.s.event(n)
	}
	if overflow {
		w.s.overflow()
	}
	if lost {
		w.s.watchFailed(errors.New("inotify: a watched directory was removed, moved or unmounted"))
	}
}

func (w *inotifyWatcher) close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()
	_ = w.f.Close()
	<-w.done
}
