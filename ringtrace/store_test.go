package ringtrace

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncGate is a chain sync hook that holds back the syncs of one path
// until released, passing every sync through to the platform.
type syncGate struct {
	path    string
	fail    error
	reached chan struct{}
	release chan struct{}
	once    sync.Once
	done    atomic.Bool
}

func newSyncGate(path string) *syncGate {
	return &syncGate{path: path, reached: make(chan struct{}), release: make(chan struct{})}
}

func (g *syncGate) hook(path string, f *os.File) error {
	if path == g.path {
		g.once.Do(func() { close(g.reached) })
		<-g.release
		defer g.done.Store(true)
		if g.fail != nil {
			return g.fail
		}
	}
	if f == nil {
		return nil
	}
	return f.Sync()
}

func setSyncHook(t *testing.T, hook func(string, *os.File) error) {
	t.Helper()
	SetChainSyncHook(hook)
	t.Cleanup(func() { SetChainSyncHook(nil) })
}

// writeChainAsync runs WriteChain on a goroutine; the channel carries its
// error.
func writeChainAsync(root string, der []byte) chan error {
	done := make(chan error, 1)
	go func() {
		_, err := WriteChain(root, der)
		done <- err
	}()
	return done
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: not within 5 s", what)
	}
}

// A handshake whose chain is stored already does not wait for the write
// of another chain, nor does the first write of a third.
func TestWriteChainDoesNotWaitForAnotherChain(t *testing.T) {
	root := t.TempDir()
	x, y, z := []byte("chain x"), []byte("chain y"), []byte("chain z")
	if _, err := WriteChain(root, y); err != nil {
		t.Fatal(err)
	}
	g := newSyncGate(filepath.Join(root, ChainsDirName, ChainHash(x)+".tmp"))
	setSyncHook(t, g.hook)
	xDone := writeChainAsync(root, x)
	waitFor(t, g.reached, "the sync of x's file")
	for _, c := range []struct {
		what string
		der  []byte
	}{{"a stored chain", y}, {"a first-seen chain", z}} {
		select {
		case err := <-writeChainAsync(root, c.der):
			if err != nil {
				t.Fatalf("%s: %v", c.what, err)
			}
		case <-time.After(2 * time.Second):
			close(g.release)
			<-xDone
			t.Fatalf("%s waited for the write of another chain", c.what)
		}
	}
	close(g.release)
	if err := <-xDone; err != nil {
		t.Fatal(err)
	}
}

// A second writer of a chain whose first write has renamed it but not yet
// synced its directory does not return until that sync has.
func TestWriteChainSameChainWaitsForTheDirectorySync(t *testing.T) {
	if !hasDirSync {
		t.Log("no directory sync here: the hook is still told, with a nil file, in the same place")
	}
	root := t.TempDir()
	x := []byte("chain x")
	if _, err := WriteChain(root, []byte("the store exists")); err != nil {
		t.Fatal(err)
	}
	g := newSyncGate(filepath.Join(root, ChainsDirName))
	setSyncHook(t, g.hook)
	first := writeChainAsync(root, x)
	waitFor(t, g.reached, "the first write's directory sync")
	if _, err := os.Lstat(ChainPath(root, ChainHash(x))); err != nil {
		t.Fatalf("the first write has not renamed yet: %v", err)
	}
	second := writeChainAsync(root, x)
	select {
	case err := <-second:
		close(g.release)
		<-first
		t.Fatalf("the second write returned (%v) before the first's directory sync", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(g.release)
	for i, ch := range []chan error{first, second} {
		if err := <-ch; err != nil {
			t.Fatalf("write %d: %v", i+1, err)
		}
	}
	if !g.done.Load() {
		t.Fatal("a write returned before the directory sync")
	}
}

// A directory sync that fails fails the writers waiting on it with its
// error, and every later write into that store.
func TestWriteChainDirectorySyncFailureIsSticky(t *testing.T) {
	root := t.TempDir()
	x := []byte("chain x")
	if _, err := WriteChain(root, []byte("the store exists")); err != nil {
		t.Fatal(err)
	}
	g := newSyncGate(filepath.Join(root, ChainsDirName))
	g.fail = errors.New("injected")
	setSyncHook(t, g.hook)
	first := writeChainAsync(root, x)
	waitFor(t, g.reached, "the first write's directory sync")
	second := writeChainAsync(root, x)
	time.Sleep(50 * time.Millisecond)
	close(g.release)
	for i, ch := range []chan error{first, second} {
		if err := <-ch; err == nil || !strings.Contains(err.Error(), "injected") {
			t.Fatalf("write %d: %v, want the failed sync", i+1, err)
		}
	}
	SetChainSyncHook(nil)
	for _, der := range [][]byte{x, []byte("the store exists"), []byte("chain y")} {
		if _, err := WriteChain(root, der); err == nil || !strings.Contains(err.Error(), "injected") {
			t.Fatalf("a write after the failed sync: %v, want the failed sync", err)
		}
	}
	// The other store under the root is its own.
	if _, err := WriteMaterial(root, []byte("material")); err != nil {
		t.Fatal(err)
	}
}

// Concurrent first-ever writes of different chains create the store once,
// and none returns before the root's sync after its creation.
func TestWriteChainFirstWritesCreateTheStoreOnce(t *testing.T) {
	root := t.TempDir()
	var synced atomic.Bool
	var rootSyncs atomic.Int64
	setSyncHook(t, func(path string, f *os.File) error {
		if path == root {
			rootSyncs.Add(1)
			time.Sleep(100 * time.Millisecond)
			defer synced.Store(true)
		}
		if f == nil {
			return nil
		}
		return f.Sync()
	})
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := WriteChain(root, []byte(fmt.Sprintf("chain %d", i))); err != nil {
				errs <- err
				return
			}
			if !synced.Load() {
				errs <- fmt.Errorf("chain %d returned before the root's sync", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := rootSyncs.Load(); got != 1 {
		t.Fatalf("%d root syncs, want 1", got)
	}
	entries, err := os.ReadDir(filepath.Join(root, ChainsDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("chains/ holds %d entries, want %d", len(entries), n)
	}
}

// A root sync that fails after the store's directory was created fails
// every later write into that store.
func TestWriteChainRootSyncFailureIsSticky(t *testing.T) {
	root := t.TempDir()
	setSyncHook(t, func(path string, f *os.File) error {
		if path == root {
			return errors.New("injected")
		}
		if f == nil {
			return nil
		}
		return f.Sync()
	})
	if _, err := WriteChain(root, []byte("chain x")); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("got %v, want the failed sync", err)
	}
	SetChainSyncHook(nil)
	if _, err := WriteChain(root, []byte("chain y")); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("a write after the failed sync: %v, want the failed sync", err)
	}
}

// A named pipe where a directory the stores and the emitter sync belongs is
// refused at once, not waited on.
func TestSyncDirRefusesANamedPipe(t *testing.T) {
	if noFIFO != "" {
		t.Skip(noFIFO)
	}
	path := filepath.Join(t.TempDir(), ChainsDirName)
	if err := mkfifo(path); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what string
		sync func(string) error
	}{
		{"syncDir", syncDir},
		{"syncChainDir", func(p string) error {
			SetChainSyncHook(func(string, *os.File) error { return nil })
			defer SetChainSyncHook(nil)
			return syncChainDir(p)
		}},
	} {
		done := make(chan error, 1)
		go func() { done <- c.sync(path) }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s synced a named pipe", c.what)
			}
		case <-time.After(5 * time.Second):
			releaseFIFO(path)
			<-done
			t.Fatalf("%s still waiting after 5 s on a named pipe", c.what)
		}
	}
}
