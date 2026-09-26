// Command bench compares an upstream ghostunnel ("base") with the
// fork ("fork"): it runs the trees' own Go benchmarks and an
// end-to-end measurement through the real binaries, and prints the results
// side by side. Standard library only; loopback only unless -backend names
// a remote echo (which -serve-echo runs on another host); writes only under
// its work directory (-work, default work/ beside the source).
//
// The tool is its own module, nested in the repository it measures, so its
// dependencies stay out of the main module. It never imports the trees: it
// checks them out into worktrees and runs go build and go test there.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// options are the run's flags as given (or as -quick rewrote them).
type options struct {
	repo    string
	base    string
	fork    string
	count   int
	conns   int
	bulkMiB int
	quick   bool
	work    string
	skipGo  bool
	skipE2E bool
	// backend, when set, is a remote echo to dial instead of the loopback
	// one the tool starts; serveEcho makes this invocation be that echo.
	backend   string
	serveEcho string
	// order is how the end-to-end runs are taken: "abba" interleaves the
	// trees run by run (base, fork, fork, base, ...), "sequential" takes
	// every run of one tree and then every run of the other.
	order string
	// forkArgs are extra flags appended to the fork proxy's command line
	// (e.g. "--warm-backend-connections 16"); the base gets none, so the
	// report compares the base as it is with the fork as configured.
	forkArgs string
}

// treeResult is everything one tree produced.
type treeResult struct {
	name    string // "base" or "fork"
	ref     string
	dir     string
	commit  commitInfo
	gobench map[string]benchStat // key: pkg.Benchmark (cpu suffix removed)
	goRaw   string
	goErr   error
	e2e     *e2eResult
	e2eErr  error // the tree could not be measured (reported, not fatal)
	trace   *traceStat
	pool    string // the fork's "warm backend pool:" log line, as it decided
}

func progress(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[bench %s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "bench: %v\n", err)
		os.Exit(1)
	}
}

func sourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
}

func run() error {
	var o options
	defaultRepo := filepath.Dir(sourceDir()) // the repository this tool lives in
	flag.StringVar(&o.repo, "repo", defaultRepo, "path of the repository that holds both refs")
	flag.StringVar(&o.base, "base", "", "base ref (default: merge-base of the fork ref and origin/master)")
	flag.StringVar(&o.fork, "fork", "portal", "fork ref")
	flag.IntVar(&o.count, "count", 5, "runs per benchmark and per measurement (median taken)")
	flag.IntVar(&o.conns, "conns", 300, "sequential connections for the churn measurement")
	flag.IntVar(&o.bulkMiB, "bulk", 64, "MiB streamed through one connection for the bulk measurement")
	flag.BoolVar(&o.quick, "quick", false, "count 2, conns 100, bulk 16")
	flag.StringVar(&o.work, "work", filepath.Join(sourceDir(), "work"), "work directory (worktrees, binaries, store tree, results)")
	flag.BoolVar(&o.skipGo, "skip-gobench", false, "skip the trees' own Go benchmarks")
	flag.BoolVar(&o.skipE2E, "skip-e2e", false, "skip the end-to-end measurement")
	flag.StringVar(&o.backend, "backend", "", "host:port of a remote echo backend (started elsewhere with -serve-echo) instead of the loopback one")
	flag.StringVar(&o.serveEcho, "serve-echo", "", "be the echo backend on this address (e.g. :9000) and never return; for a second host")
	flag.StringVar(&o.order, "order", "abba", "end-to-end run order: abba (interleaved, base fork fork base ...) or sequential (all base runs, then all fork runs)")
	flag.StringVar(&o.forkArgs, "fork-args", "", "extra flags for the fork proxy only, space-separated (e.g. \"--warm-backend-connections 16\")")
	flag.Parse()
	if o.order != "abba" && o.order != "sequential" {
		return fmt.Errorf("-order must be abba or sequential")
	}
	if o.serveEcho != "" {
		echo, err := startEchoOn(o.serveEcho)
		if err != nil {
			return fmt.Errorf("echo backend: %w", err)
		}
		progress("echo backend serving on %s; ctrl-c to stop", echo.addr)
		select {}
	}
	if o.quick {
		o.count, o.conns, o.bulkMiB = 2, 100, 16
	}
	if o.count < 1 || o.conns < 16 || o.bulkMiB < 1 {
		return fmt.Errorf("-count must be >= 1, -conns >= 16, -bulk >= 1")
	}
	work, err := filepath.Abs(o.work)
	if err != nil {
		return err
	}
	o.work = work
	if err := os.MkdirAll(filepath.Join(work, "results"), 0o755); err != nil {
		return err
	}
	disk := describeDisk(work)
	progress("work %s (%s): fsync %s", disk.dir, orUnknown(disk.fs), disk.fsyncString())
	if disk.slow() {
		progress("WARNING: fsync above %s on the work volume; the fork's trace pays it per connection", fsyncWarnAt)
	}
	if o.base == "" {
		mb, err := gitOutput(o.repo, "merge-base", o.fork, "origin/master")
		if err != nil {
			return fmt.Errorf("computing the default base ref: %w", err)
		}
		o.base = strings.TrimSpace(mb)
	}
	started := time.Now()
	stamp := started.Format("20060102-150405")

	// 1. Worktrees.
	trees := []*treeResult{
		{name: "base", ref: o.base, dir: filepath.Join(work, "base")},
		{name: "fork", ref: o.fork, dir: filepath.Join(work, "fork")},
	}
	for _, t := range trees {
		progress("worktree %s at %s (%s)", t.name, t.dir, t.ref)
		if err := addWorktree(o.repo, t.dir, t.ref); err != nil {
			return fmt.Errorf("worktree %s: %w", t.name, err)
		}
		ci, err := describeCommit(t.dir)
		if err != nil {
			return fmt.Errorf("describing %s: %w", t.name, err)
		}
		t.commit = ci
		progress("%s = %s %s %s", t.name, ci.hash[:12], ci.date, ci.subject)
	}

	// 3 (run before 2). End to end through the real binaries. This runs
	// first because the trees' own connection-churn benchmarks leave
	// thousands of loopback sockets in TIME_WAIT, which exhausts the
	// ephemeral port pool for minutes and would poison the end-to-end
	// numbers of whichever tree came next; the report keeps the order.
	if !o.skipE2E {
		if err := runE2E(&o, trees); err != nil {
			return err
		}
	}

	// 2. The trees' own Go benchmarks.
	if !o.skipGo {
		for _, t := range trees {
			pkgs, err := benchmarkPackages(t.dir)
			if err != nil {
				t.goErr = err
				continue
			}
			progress("%s: go test -bench in %d package(s): %s", t.name, len(pkgs), strings.Join(pkgs, " "))
			raw, err := runGoBench(t.dir, pkgs, o.count)
			t.goRaw = raw
			rawPath := filepath.Join(work, "results", stamp+"-"+t.name+"-gobench.txt")
			if werr := os.WriteFile(rawPath, []byte(raw), 0o644); werr != nil {
				return werr
			}
			if err != nil {
				t.goErr = err
				progress("%s: go test -bench failed: %v", t.name, err)
			}
			t.gobench = parseBenchOutput(raw)
			progress("%s: %d benchmark(s) parsed", t.name, len(t.gobench))
		}
	}

	// 4. Output.
	report := renderReport(&o, disk, trees, started)
	fmt.Print(report)
	out := filepath.Join(work, "results", stamp+".txt")
	if err := os.WriteFile(out, []byte(report), 0o644); err != nil {
		return err
	}
	progress("report written to %s", out)
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "filesystem not determined"
	}
	return s
}

func renderReport(o *options, disk *diskInfo, trees []*treeResult, started time.Time) string {
	var b strings.Builder
	base, fork := trees[0], trees[1]
	fmt.Fprintf(&b, "ghostunnel benchmark: base vs fork\n")
	fmt.Fprintf(&b, "================================================\n\n")
	fmt.Fprintf(&b, "started   %s\n", started.Format(time.RFC3339))
	fmt.Fprintf(&b, "finished  %s (%s)\n", time.Now().Format(time.RFC3339), time.Since(started).Round(time.Second))
	fmt.Fprintf(&b, "host      %s/%s, %d CPUs, %s\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	fmt.Fprintf(&b, "repo      %s\n", o.repo)
	for _, t := range trees {
		fmt.Fprintf(&b, "%-9s %s\n", t.name, t.ref)
		fmt.Fprintf(&b, "          %s  %s\n", t.commit.hash, t.commit.date)
		fmt.Fprintf(&b, "          %s\n", t.commit.subject)
	}
	fmt.Fprintf(&b, "flags     -count %d -conns %d -bulk %d", o.count, o.conns, o.bulkMiB)
	if o.quick {
		b.WriteString(" (-quick)")
	}
	b.WriteString("\n")
	if o.order == "abba" {
		b.WriteString("order     interleaved: base, fork, fork, base, ... (both proxies up throughout)\n")
	} else {
		b.WriteString("order     sequential: every base run, then every fork run (both proxies up throughout)\n")
	}
	if o.forkArgs != "" {
		fmt.Fprintf(&b, "fork-args %s (the fork as configured against the base as it is)\n", o.forkArgs)
	}
	if fork.pool != "" {
		fmt.Fprintf(&b, "fork-pool %s\n", fork.pool)
	}
	if o.backend != "" {
		fmt.Fprintf(&b, "backend   remote %s (an echo on another host; the dial crosses the network)\n", o.backend)
	} else {
		b.WriteString("backend   loopback (an echo in this process on the loopback interface; the dial never leaves the host)\n")
	}
	fmt.Fprintf(&b, "work      %s (%s)\n", disk.dir, orUnknown(disk.fs))
	fmt.Fprintf(&b, "fsync     %s\n", disk.fsyncString())
	if disk.slow() {
		fmt.Fprintf(&b, "WARNING   fsync on the work volume is above %s; the fork's trace pays it on every\n", fsyncWarnAt)
		b.WriteString("          connection, so its end-to-end numbers measure this disk, not the fork. Put\n")
		b.WriteString("          -work on a faster volume and run again.\n")
	}
	b.WriteString("\n")

	// Go benchmarks.
	fmt.Fprintf(&b, "Go benchmarks (median of %d runs; ns/op, B/op, allocs/op)\n", o.count)
	fmt.Fprintf(&b, "---------------------------------------------------------\n")
	if o.skipGo {
		b.WriteString("skipped (-skip-gobench)\n\n")
	} else {
		for _, t := range trees {
			if t.goErr != nil {
				fmt.Fprintf(&b, "%s: go test -bench reported an error: %v (parsed what it printed)\n", t.name, t.goErr)
			}
		}
		b.WriteString(renderGoBenchTable(base.gobench, fork.gobench))
		b.WriteString("\n")
	}

	// End to end.
	fmt.Fprintf(&b, "End to end through the binaries (median of %d runs)\n", o.count)
	fmt.Fprintf(&b, "---------------------------------------------------\n")
	if o.skipE2E {
		b.WriteString("skipped (-skip-e2e)\n\n")
	} else {
		for _, t := range trees {
			if t.e2eErr != nil {
				fmt.Fprintf(&b, "%s: not measured on this host: %v\n", t.name, t.e2eErr)
			}
		}
		b.WriteString(renderE2ETable(base.e2e, fork.e2e))
		b.WriteString("\n")
		if fork.trace != nil {
			fmt.Fprintf(&b, "fork trace after the run: %s bytes under gt/, %s lines",
				commas(fork.trace.bytes), commas(fork.trace.lines))
			if fork.e2e != nil && fork.e2e.totalConns > 0 {
				fmt.Fprintf(&b, " (%d connections served: %.1f lines and %.0f bytes per connection, start line included)",
					fork.e2e.totalConns,
					float64(fork.trace.lines)/float64(fork.e2e.totalConns),
					float64(fork.trace.bytes)/float64(fork.e2e.totalConns))
			}
			b.WriteString("\n\n")
		}
	}

	b.WriteString("Caveats\n")
	b.WriteString("-------\n")
	b.WriteString("A loaded machine inflates both columns; only a quiet host gives a fair delta, and the\n")
	b.WriteString("median of a small -count still moves between runs. The end-to-end numbers include what\n")
	b.WriteString("the fork does per connection that the base does not: the gate's reads of the store tree\n")
	b.WriteString("on every accept (four member stores and the coordinator's newest heartbeat) and the trace\n")
	b.WriteString("lines it appends, fsynced one by one, per accept, handshake and access decision. The Go\n")
	b.WriteString("benchmarks measure the packages as they are in each tree and are not touched by the ring.\n")
	return b.String()
}
