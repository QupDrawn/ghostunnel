package ringtrace

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// stateClock is a clock the tests move by hand: the state's freshness clock
// and the gate's heartbeat clock are the same one, so the heartbeat written
// by healthyTree (gateNow minus two seconds) is judged against it too.
type stateClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stateClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stateClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// testState is a GateState over a healthy tree with a 10 ms window, a 1 s
// MaxAge and the hand-moved clock; no watcher unless the test starts one.
func testState(t *testing.T) (*GateState, string, *stateClock) {
	t.Helper()
	root := healthyTree(t)
	clock := &stateClock{now: gateNow}
	g := testGate(root)
	g.Now = clock.Now
	s := NewGateState(g, 10*time.Millisecond, time.Second)
	s.Now = clock.Now
	t.Cleanup(s.Close)
	return s, root, clock
}

// fakeWatcher is a watcher that reports whatever the test says and never
// sees the tree: what it simulates is a change the kernel does not report.
type fakeWatcher struct{ polls int }

func (w *fakeWatcher) poll()  { w.polls++ }
func (w *fakeWatcher) close() {}

func placeHalt(t *testing.T, root string) {
	t.Helper()
	writeRaw(t, filepath.Join(root, "material", "halt"), `{"kind":"halt",`)
}

// TestGateStateCoalescesConcurrentChecks: sixteen callers arriving while
// one scan is in flight share its result; one scan, sixteen decisions.
func TestGateStateCoalescesConcurrentChecks(t *testing.T) {
	s, _, _ := testState(t)
	const callers = 16
	var arrived sync.WaitGroup
	arrived.Add(callers - 1)
	release := make(chan struct{})
	s.scanHook = func() {
		// The first caller is inside its scan; hold it until every other
		// caller has arrived and is waiting.
		arrived.Wait()
		<-release
	}
	var wg sync.WaitGroup
	decisions := make([]Decision, callers)
	wg.Add(1)
	go func() { defer wg.Done(); decisions[0] = s.Check() }()
	// The leader's scan is in flight once scanHook is entered; the others
	// arrive behind it.
	for i := 1; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			arrived.Done()
			decisions[i] = s.Check()
		}(i)
	}
	arrived.Wait()
	time.Sleep(20 * time.Millisecond) // let the followers reach the wait
	close(release)
	wg.Wait()
	for i, d := range decisions {
		if !d.Serve {
			t.Fatalf("caller %d refused: %s", i, d.Reason)
		}
	}
	if got := s.Scans(); got != 1 {
		t.Fatalf("%d scans for %d concurrent checks, want 1", got, callers)
	}
}

// TestGateStateWindowReuse: without a watcher, a check within the window
// of the last scan reuses it; one after the window scans again.
func TestGateStateWindowReuse(t *testing.T) {
	s, _, clock := testState(t)
	if d := s.Check(); !d.Serve {
		t.Fatal(d.Reason)
	}
	clock.Advance(time.Millisecond)
	s.Check()
	if got := s.Scans(); got != 1 {
		t.Fatalf("%d scans for two checks 1 ms apart, want 1", got)
	}
	clock.Advance(20 * time.Millisecond)
	s.Check()
	if got := s.Scans(); got != 2 {
		t.Fatalf("%d scans after a check 20 ms later, want 2", got)
	}
}

// TestGateStateStaleDecisionIsNotReused: an event marks the decision stale;
// the next check scans, inside the window or not, and sees the halt.
func TestGateStateStaleDecisionIsNotReused(t *testing.T) {
	s, root, clock := testState(t)
	w := &fakeWatcher{}
	s.setWatcher(w)
	if d := s.Check(); !d.Serve {
		t.Fatal(d.Reason)
	}
	placeHalt(t, root)
	clock.Advance(time.Millisecond)
	if d := s.Check(); !d.Serve {
		t.Fatalf("no event was reported: the decision must still be reused, got %s", d.Reason)
	}
	s.event(1)
	clock.Advance(time.Millisecond)
	d := s.Check()
	if d.Serve {
		t.Fatal("served on a stale decision after an event")
	}
	if d.Reason != "gate: material/halt in force" {
		t.Fatalf("reason %q", d.Reason)
	}
	if got := s.Scans(); got != 2 {
		t.Fatalf("%d scans, want 2", got)
	}
	if w.polls < 3 {
		t.Fatalf("the watcher was polled %d times on 3 checks: every check must drain what the kernel has ready", w.polls)
	}
}

// TestGateStateBoundWithoutEvents: a watcher that never reports (a change
// the kernel does not see) leaves the decision reused for MaxAge at most;
// the check after that scans and refuses. Never later.
func TestGateStateBoundWithoutEvents(t *testing.T) {
	s, root, clock := testState(t)
	s.setWatcher(&fakeWatcher{})
	if d := s.Check(); !d.Serve {
		t.Fatal(d.Reason)
	}
	placeHalt(t, root)
	clock.Advance(s.MaxAge)
	if d := s.Check(); !d.Serve {
		t.Fatalf("at MaxAge exactly the decision is still within its bound, got %s", d.Reason)
	}
	if got := s.Scans(); got != 1 {
		t.Fatalf("%d scans, want 1", got)
	}
	clock.Advance(time.Nanosecond)
	if d := s.Check(); d.Serve {
		t.Fatal("served past MaxAge with a halt in force: the fallback scan did not run")
	}
	if got := s.Scans(); got != 2 {
		t.Fatalf("%d scans, want 2", got)
	}
}

// TestGateStateWatcherFailureScansEveryCheck: once the watcher has failed
// only the window stands; every check outside it scans. An overflow marks
// the decision stale and the next check scans.
func TestGateStateWatcherFailureScansEveryCheck(t *testing.T) {
	s, _, clock := testState(t)
	s.setWatcher(&fakeWatcher{})
	s.Check()
	clock.Advance(100 * time.Millisecond)
	s.Check()
	if got := s.Scans(); got != 1 {
		t.Fatalf("%d scans with a healthy silent watcher 100 ms apart, want 1", got)
	}
	s.overflow()
	if d := s.Check(); !d.Serve {
		t.Fatal(d.Reason)
	}
	if got := s.Scans(); got != 2 {
		t.Fatalf("%d scans after an overflow, want 2", got)
	}
	s.watchFailed(errors.New("watch lost"))
	if s.Watching() {
		t.Fatal("still watching after a failure")
	}
	for i := 0; i < 5; i++ {
		clock.Advance(11 * time.Millisecond)
		s.Check()
	}
	if got := s.Scans(); got != 7 {
		t.Fatalf("%d scans after a watcher failure and five checks outside the window, want 7", got)
	}
}

// TestGateStateHeartbeatAgeIsJudgedOnReuse: a reused serve decision still
// judges the heartbeat's age against the clock; when it has aged out the
// check scans and refuses, whatever the watcher says.
func TestGateStateHeartbeatAgeIsJudgedOnReuse(t *testing.T) {
	s, _, clock := testState(t)
	s.setWatcher(&fakeWatcher{})
	s.MaxAge = time.Hour
	if d := s.Check(); !d.Serve {
		t.Fatal(d.Reason)
	}
	// The heartbeat is 2 s old at gateNow; the gate's window is 10 s.
	clock.Advance(7 * time.Second)
	if d := s.Check(); !d.Serve {
		t.Fatalf("heartbeat 9 s old within a 10 s window: %s", d.Reason)
	}
	clock.Advance(2 * time.Second)
	d := s.Check()
	if d.Serve {
		t.Fatal("served on a heartbeat 11 s old under a 10 s window")
	}
	if got := s.Scans(); got != 2 {
		t.Fatalf("%d scans, want 2", got)
	}
}

// TestGateStateScanIsAlwaysFresh: Scan never reuses; it is what the
// proxy's watch calls every interval to refresh the state.
func TestGateStateScanIsAlwaysFresh(t *testing.T) {
	s, root, _ := testState(t)
	s.setWatcher(&fakeWatcher{})
	if d := s.Scan(); !d.Serve {
		t.Fatal(d.Reason)
	}
	placeHalt(t, root)
	if d := s.Scan(); d.Serve {
		t.Fatal("Scan reused a decision")
	}
	if got := s.Scans(); got != 2 {
		t.Fatalf("%d scans, want 2", got)
	}
	// And it refreshed the state: the next Check reuses the refusal.
	if d := s.Check(); d.Serve || s.Scans() != 2 {
		t.Fatalf("Check after Scan: serve=%v scans=%d", d.Serve, s.Scans())
	}
}

// TestGateStateWatcherReportsTheTree: the real watcher on this OS. A halt
// placed after a serve decision is reported, and the next check scans and
// refuses; removing it and writing a fresh heartbeat is reported too.
func TestGateStateWatcherReportsTheTree(t *testing.T) {
	s, root, clock := testState(t)
	err := s.Watch()
	switch runtime.GOOS {
	case "linux", "windows":
		if err != nil {
			t.Fatalf("Watch on %s: %v", runtime.GOOS, err)
		}
	default:
		if err == nil {
			t.Fatalf("Watch on %s must report that there is no watcher", runtime.GOOS)
		}
		t.Skip("no watcher on this OS")
	}
	if !s.Watching() {
		t.Fatal("not watching")
	}
	if d := s.Check(); !d.Serve {
		t.Fatal(d.Reason)
	}
	// Windows reports a file's last-write change only when the cache
	// flushes, so the tree healthyTree wrote may still report; names (what
	// decides the gate) are reported at once. Let it, absorb it, and count
	// scans relative to that.
	time.Sleep(100 * time.Millisecond)
	s.Check()
	scans, events := s.Scans(), s.Events()
	placeHalt(t, root)
	waitEvents(t, s, events)
	clock.Advance(time.Millisecond)
	if d := s.Check(); d.Serve {
		t.Fatal("served after the watcher reported the halt")
	}
	if got := s.Scans(); got != scans+1 {
		t.Fatalf("%d scans, want %d", got, scans+1)
	}
	scans, events = s.Scans(), s.Events()
	if err := os.Remove(filepath.Join(root, "material", "halt")); err != nil {
		t.Fatal(err)
	}
	writeHB(t, root, "super", 43, gateNow.Add(-time.Second).Format("2006-01-02T15:04:05Z"), false)
	waitEvents(t, s, events)
	clock.Advance(time.Millisecond)
	if d := s.Check(); !d.Serve {
		t.Fatalf("refused after the halt was cleared: %s", d.Reason)
	}
	if got := s.Scans(); got != scans+1 {
		t.Fatalf("%d scans, want %d", got, scans+1)
	}
	// With nothing reported, checks well past the window reuse the state.
	time.Sleep(100 * time.Millisecond)
	s.Check()
	scans, events = s.Scans(), s.Events()
	clock.Advance(500 * time.Millisecond)
	s.Check()
	if s.Events() == events && s.Scans() != scans {
		t.Fatalf("%d scans on a tree that reported nothing, want %d", s.Scans(), scans)
	}
}

// waitEvents blocks until the watcher has consumed an event beyond the
// count given, or fails after two seconds.
func waitEvents(t *testing.T, s *GateState, before int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for s.Events() == before {
		if time.Now().After(deadline) {
			t.Fatalf("no event within 2 s (%d before)", before)
		}
		time.Sleep(time.Millisecond)
	}
}
