package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

// A child is a process the tool started and must not outlive it: a proxy,
// or the go test behind -gobench. The tool's own deferred cleanup does not
// run when it is interrupted, so every child is registered from the moment
// it starts, and watchSignals stops all of them before the tool exits.
type child interface{ stop() }

var children = struct {
	sync.Mutex
	set      map[child]struct{}
	stopping bool
}{set: map[child]struct{}{}}

var errStopping = errors.New("the tool is stopping; no process started")

// startChild starts cmd and registers c as its child in one step, under the
// registry's lock, so an interrupt cannot fall between the two and leave a
// process nobody stops. Once the tool is stopping nothing starts.
func startChild(cmd *exec.Cmd, c child) error {
	children.Lock()
	defer children.Unlock()
	if children.stopping {
		return errStopping
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	children.set[c] = struct{}{}
	return nil
}

// releaseChild forgets c once it has been stopped or has exited.
func releaseChild(c child) {
	children.Lock()
	delete(children.set, c)
	children.Unlock()
}

// stopChildren refuses every later start and stops every registered child.
func stopChildren() {
	children.Lock()
	children.stopping = true
	all := make([]child, 0, len(children.set))
	for c := range children.set {
		all = append(all, c)
	}
	children.Unlock()
	for _, c := range all {
		c.stop()
	}
}

// watchSignals stops every child and exits on the first of stopSignals: an
// interrupt, or on unix a terminate or the hangup of a closed ssh session.
// The exit status is 128 plus the signal's number, as a shell reports it.
func watchSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, stopSignals...)
	go func() {
		s := <-ch
		progress("%s: stopping every process this run started", s)
		stopChildren()
		code := 1
		if n, ok := s.(syscall.Signal); ok {
			code = 128 + int(n)
		}
		os.Exit(code)
	}()
}

// goTest is the go test behind -gobench, a child like the proxies. Killing
// the go command alone would leave the test binary it runs, so on unix it
// runs in its own process group and the whole group is killed.
type goTest struct {
	cmd  *exec.Cmd
	once sync.Once
}

func (g *goTest) stop() {
	g.once.Do(func() { killTree(g.cmd) })
}
