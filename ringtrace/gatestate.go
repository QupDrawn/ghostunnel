package ringtrace

// gatestate.go is the gate as a trivial call: the state the proxy keeps
// over Gate.Check so that the check on the accept path reads a mutex and a
// clock, not the store tree. Nothing here decides anything: every decision
// is one Gate.Check made, and the state only says how long it stands.
//
// A decision stands (is reused by a Check) while all of these hold:
//   - no change notification has arrived since the scan that made it
//     (the OS watcher bumps a generation on every event; a queue overflow
//     or a watcher error bumps it too, so nothing lost goes unnoticed);
//   - it is younger than Window, or the watcher is running without error
//     and it is younger than MaxAge, the interval at which the caller's
//     watch calls Scan and refreshes it regardless;
//   - when it is a serve decision, the heartbeat it rests on is still
//     within the gate's window by the gate's clock, judged afresh on every
//     reuse.
// Anything else is a full scan, and concurrent callers share one: the
// first to arrive runs Gate.Check, the ones arriving meanwhile wait for
// that read and take its decision. A caller never waits for anything but
// the one read it started or joined.
//
// The bound this puts on a change the kernel does not report (a write
// through a shared mapping without msync, a mount over a watched
// directory, a watcher that is not running) is MaxAge: the next Scan sees
// it. A change the kernel reports is seen by the next Check, since every
// Check first drains what the kernel has ready. Nothing is keyed on a
// size or a modification time.

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// GateState is the proxy-maintained state of a Gate. Window and MaxAge
// are read once at construction; the exported fields are for tests.
type GateState struct {
	// Gate is what every scan calls.
	Gate *Gate
	// Window is how long a decision is reused with no watcher running (or
	// a failed one): concurrent callers and a burst share one scan.
	Window time.Duration
	// MaxAge is how long a decision is reused with the watcher running and
	// silent; the caller's watch calls Scan at least this often.
	MaxAge time.Duration
	// Now is the clock the decision's age is judged by.
	Now func() time.Time

	mu         sync.Mutex
	inflight   *gateScan
	valid      bool
	decision   Decision
	decidedAt  time.Time
	decidedGen uint64
	gen        uint64
	watcher    treeWatcher
	watchErr   error

	scans     atomic.Int64
	events    atomic.Int64
	overflows atomic.Int64
	// scanHook, when set, runs inside every scan (a test seam that holds a
	// scan open while callers queue behind it).
	scanHook func()
}

// gateScan is one Gate.Check in flight; done is closed once decision is set.
type gateScan struct {
	done     chan struct{}
	decision Decision
}

// treeWatcher is the OS's change notification on the store tree. poll
// consumes, without blocking, every event the kernel has ready and reports
// each to the state; a goroutine of the watcher's own does the same for
// events arriving while nobody checks. close stops it.
type treeWatcher interface {
	poll()
	close()
}

// NewGateState returns the state over g with the given window and bound.
func NewGateState(g *Gate, window, maxAge time.Duration) *GateState {
	return &GateState{Gate: g, Window: window, MaxAge: maxAge, Now: time.Now}
}

// Check is the accept path's call: the standing decision when one stands,
// else one full scan shared with every caller that arrives meanwhile.
func (s *GateState) Check() Decision {
	return s.check(false)
}

// Scan is the caller's watch's call: always a full scan (or the one in
// flight), and the state is refreshed from it.
func (s *GateState) Scan() Decision {
	return s.check(true)
}

func (s *GateState) check(force bool) Decision {
	if s == nil || s.Gate == nil {
		return refuse("gate: no gate")
	}
	s.mu.Lock()
	w := s.watcher
	s.mu.Unlock()
	if w != nil {
		w.poll()
	}
	s.mu.Lock()
	if !force {
		if d, ok := s.standingLocked(); ok {
			s.mu.Unlock()
			return d
		}
	}
	if in := s.inflight; in != nil {
		s.mu.Unlock()
		<-in.done
		return in.decision
	}
	in := &gateScan{done: make(chan struct{})}
	s.inflight = in
	gen := s.gen
	s.mu.Unlock()

	s.scans.Add(1)
	if s.scanHook != nil {
		s.scanHook()
	}
	d := s.Gate.Check()
	at := s.now()

	s.mu.Lock()
	s.inflight = nil
	s.valid, s.decision, s.decidedAt, s.decidedGen = true, d, at, gen
	s.mu.Unlock()
	in.decision = d
	close(in.done)
	return d
}

// standingLocked reports the decision that stands, if one does. The
// caller holds s.mu.
func (s *GateState) standingLocked() (Decision, bool) {
	if !s.valid || s.gen != s.decidedGen {
		return Decision{}, false
	}
	age := s.now().Sub(s.decidedAt)
	if age < 0 {
		return Decision{}, false
	}
	watching := s.watcher != nil && s.watchErr == nil
	if age > s.Window && (!watching || age > s.MaxAge) {
		return Decision{}, false
	}
	if s.decision.Serve {
		// The heartbeat's age is never cached: judged by the gate's clock,
		// in both directions, as Gate.Check judges it.
		if s.decision.hbAt.IsZero() || s.Gate.Now == nil || s.Gate.MaxHeartbeatAge <= 0 {
			return Decision{}, false
		}
		hbAge := s.Gate.Now().UTC().Sub(s.decision.hbAt)
		if hbAge > s.Gate.MaxHeartbeatAge || -hbAge > s.Gate.MaxHeartbeatAge {
			return Decision{}, false
		}
	}
	return s.decision, true
}

func (s *GateState) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// Watch starts the OS's change notification on the tree the gate reads:
// the root, every member's store and halts/, and the coordinator's
// heartbeat/. An error means no watcher: every Check outside the window
// is then a full scan, and the caller logs why.
func (s *GateState) Watch() error {
	if s.Gate == nil {
		return errors.New("gate state: no gate")
	}
	g := s.Gate
	dirs := []string{g.Root}
	for _, m := range g.Members {
		dirs = append(dirs, filepath.Join(g.Root, m), filepath.Join(g.Root, m, "halts"))
	}
	dirs = append(dirs, filepath.Join(g.Root, g.Coordinator, "heartbeat"))
	w, err := startWatcher(g.Root, dirs, s)
	if err != nil {
		return err
	}
	s.setWatcher(w)
	return nil
}

// setWatcher installs w and marks the state stale, so the first Check
// after it scans under the watch.
func (s *GateState) setWatcher(w treeWatcher) {
	s.mu.Lock()
	old := s.watcher
	s.watcher, s.watchErr = w, nil
	s.gen++
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
}

// Close stops the watcher.
func (s *GateState) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	w := s.watcher
	s.watcher = nil
	s.mu.Unlock()
	if w != nil {
		w.close()
	}
}

// event is the watcher's report of n events: the decision is stale.
func (s *GateState) event(n int) {
	s.mu.Lock()
	s.gen++
	s.mu.Unlock()
	s.events.Add(int64(n))
}

// overflow is the watcher's report that the kernel dropped events: the
// decision is stale, whatever was missed is seen by the scan that follows.
func (s *GateState) overflow() {
	s.overflows.Add(1)
	s.event(1)
}

// watchFailed is the watcher's report that it can no longer report: from
// here on only the window stands, and the first Check scans.
func (s *GateState) watchFailed(err error) {
	s.mu.Lock()
	if s.watchErr == nil {
		s.watchErr = err
	}
	s.gen++
	s.mu.Unlock()
	s.events.Add(1)
}

// Scans is how many full scans have run (a seam for tests and benchmarks).
func (s *GateState) Scans() int64 { return s.scans.Load() }

// Events is how many events the watcher has reported, overflows and its
// own failure included (a seam for tests that wait on it).
func (s *GateState) Events() int64 { return s.events.Load() }

// Overflows is how many times the watcher reported dropped events.
func (s *GateState) Overflows() int64 { return s.overflows.Load() }

// Watching reports whether a watcher is running and has not failed.
func (s *GateState) Watching() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.watcher != nil && s.watchErr == nil
}

// WatchError is the watcher's failure, if it has one.
func (s *GateState) WatchError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.watchErr
}
