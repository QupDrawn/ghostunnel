// ringstatus: what the ghostunnel observer ring looks like right now.
//
// An operator's view, not a member. It reads the store tree and prints it. It
// joins no ring, publishes nothing, holds no credential and writes no file:
// every path it touches is opened for reading, and the tests prove a render
// leaves the tree byte-for-byte and mtime-for-mtime as it found it.
//
// Why a terminal tool and not a page. Every way into the deployment is gated,
// and a gate answers 503 during a halt, which is precisely when somebody wants
// to look. The thing that watches a deployment has to work when the deployment
// does not, so this runs beside the tree, needs no listener and no proxy, and
// keeps working after the last connection has been refused.
//
// What it is not. It is not a check and its opinion is not a verdict. The
// members' own fault and halt files are the truth: they are what stopped the
// work, and anything printed here that disagrees with them is this tool being
// wrong. Where it cannot tell two things apart (a pruned heartbeat from a
// disagreement, say) it says so rather than guessing.
//
// Usage:
//
//	ringstatus [-stores DIR] [--watch] [--once] [--interval=N] [--no-color]
//
// The tree defaults to /var/lib/ghostunnel-ring/stores, or to
// GHOSTUNNEL_RING_STORES when that is set, so the tool can be pointed at a
// copied tree to look at a deployment that has since been restarted, or to see
// what a halt renders like without causing one. --watch redraws in place,
// --interval=N sets the redraw period and implies --watch, --once prints one
// frame and stops, and --once wins wherever it appears. With no argument the
// tool watches when stdout is a terminal and prints once when it is not.
// --no-color, or a NO_COLOR variable, drops the escapes.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	defaultStores   = "/var/lib/ghostunnel-ring/stores"
	storesEnv       = "GHOSTUNNEL_RING_STORES"
	timestampLayout = "2006-01-02T15:04:05Z"
	coordinator     = "super"
)

// Display order, coordinator first. This is not the ring's own order and
// nothing here changes that: reading a store is not participating in it.
// super leads because it holds the whole view and its absence alone stops
// everything, so it is the row to look at first.
var (
	members    = []string{"super", "tunnel", "admin", "material"}
	structural = []string{"tunnel", "admin", "material"}

	// copyAuthor names, for each structural member's store, the peer that
	// writes into its copy/ folder.
	copyAuthor = map[string]string{"tunnel": "material", "admin": "tunnel", "material": "admin"}
)

type options struct {
	stores   string
	watch    bool
	once     bool
	interval int
	noColor  bool
}

// parseArgs settles the options from the arguments, the environment and
// whether stdout is a screen. --once beats --watch and --interval whatever
// the order, so a launcher can pass --watch as its default and still be
// overridden on the command line.
func parseArgs(args []string, getenv func(string) (string, bool), isTerminal bool) (options, error) {
	o := options{stores: defaultStores, interval: 1}
	if v, ok := getenv(storesEnv); ok && v != "" {
		o.stores = v
	}
	if _, ok := getenv("NO_COLOR"); ok {
		o.noColor = true
	}
	fs := flag.NewFlagSet("ringstatus", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.stores, "stores", o.stores, "the store tree to read")
	fs.BoolVar(&o.watch, "watch", false, "redraw in place")
	fs.BoolVar(&o.once, "once", false, "print one frame and stop")
	interval := fs.Int("interval", 1, "seconds between redraws; implies --watch")
	fs.BoolVar(&o.noColor, "no-color", o.noColor, "no colour escapes")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "interval" {
			o.watch = true
			o.interval = *interval
			if o.interval < 1 {
				o.interval = 1
			}
		}
	})
	if !o.watch && !o.once {
		if isTerminal {
			o.watch = true
		} else {
			o.once = true
		}
	}
	if o.once {
		o.watch = false
	}
	return o, nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: ringstatus [-stores DIR] [--watch] [--once] [--interval=N] [--no-color]

  -stores DIR    the store tree to read (default `+defaultStores+`,
                 or $`+storesEnv+`)
  --watch        redraw in place; the default when stdout is a terminal
  --once         print one frame and stop; wins over --watch wherever it appears
  --interval=N   seconds between redraws, at least 1; implies --watch
  --no-color     no colour escapes; $NO_COLOR does the same
`)
}

// exitFunc is the single reference to os.Exit; every process exit goes
// through it.
var exitFunc = os.Exit //nolint:forbidigo // the one allowed os.Exit indirection

func main() {
	o, err := parseArgs(os.Args[1:], os.LookupEnv, isTerminal(os.Stdout))
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(os.Stdout)
			return
		}
		fmt.Fprintln(os.Stderr, "ringstatus:", err)
		usage(os.Stderr)
		exitFunc(2)
	}
	if !o.watch {
		runOnce(o.stores, time.Second, os.Stdout, o.noColor)
		return
	}
	watch(o)
}

// runOnce prints a single frame. There is no rate without two readings, so
// it samples the sequences, pauses, samples again and renders: a second is a
// small price for a number that is measured rather than assumed.
func runOnce(stores string, pause time.Duration, out io.Writer, noColor bool) {
	before := sampleSequences(stores)
	t0 := time.Now()
	if pause > 0 {
		time.Sleep(pause)
	}
	rates := ratesBetween(before, sampleSequences(stores), time.Since(t0).Seconds())
	w := bufio.NewWriter(out)
	for _, line := range renderLines(stores, rates, time.Now(), noColor) {
		fmt.Fprintln(w, line)
	}
	w.Flush()
}

// watch redraws in place until interrupted. Each frame measures its rates
// against the frame before it, so the cycle column is the rate over the
// interval just elapsed rather than an average since start.
//
// The cursor and the real screen both have to come back however this ends,
// including ctrl-c, or whoever ran it is left in a terminal with no cursor
// and no scrollback. The deferred leave handles every return path, and the
// signal is turned into a return rather than an exit so the defer runs.
func watch(o options) {
	term := &terminal{w: os.Stdout, screen: isTerminal(os.Stdout)}
	if term.screen {
		enableVirtualTerminal(os.Stdout)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	term.enter()
	defer term.leave()

	before := sampleSequences(o.stores)
	t0 := time.Now()
	var rates map[string]*float64
	footer := footerLine(o.interval, o.noColor)
	for {
		lines := renderLines(o.stores, rates, time.Now(), o.noColor)
		term.repaint(append(lines, footer))
		select {
		case <-sigs:
			return
		case <-time.After(time.Duration(o.interval) * time.Second):
		}
		after := sampleSequences(o.stores)
		t1 := time.Now()
		rates = ratesBetween(before, after, t1.Sub(t0).Seconds())
		before, t0 = after, t1
	}
}

// footerLine is the last line of a watched frame.
func footerLine(interval int, noColor bool) string {
	return "  " + paint(fmt.Sprintf("watching every %ds, ctrl-c to stop", interval), "grey", noColor)
}

// ---- the screen -----------------------------------------------------------

// isTerminal reports whether repainting means anything. Piped into a file or
// through a pager there is no cursor to move, so the escapes would be noise
// rather than a picture, and frames are printed one after another instead.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

type terminal struct {
	w      io.Writer
	screen bool
}

// enter switches to the alternate screen buffer, the one a pager draws into:
// a screen of its own that cannot scroll the real one, restored untouched on
// leave. It is the difference between a live view and a program that eats
// the terminal history of whoever ran it. The cursor is hidden with it.
func (t *terminal) enter() {
	if t.screen {
		_, _ = io.WriteString(t.w, "\033[?1049h\033[?25l")
	}
}

func (t *terminal) leave() {
	if t.screen {
		_, _ = io.WriteString(t.w, "\033[?25h\033[?1049l")
	}
}

// repaint draws a frame where the last one was: home the cursor, write each
// line followed by erase-to-end-of-line, then erase whatever is left below.
// Nothing is cleared before it is replaced, so there is no blank frame and
// no flicker.
//
// The last line is written without a newline. A newline on the final row of
// a full window scrolls the whole screen by one, and homing the cursor then
// lands a row above where the previous frame started, which draws the header
// twice.
func (t *terminal) repaint(lines []string) {
	if !t.screen {
		var b strings.Builder
		for _, line := range lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
		_, _ = io.WriteString(t.w, b.String())
		return
	}
	var b strings.Builder
	b.WriteString("\033[H")
	for i, line := range lines {
		b.WriteString(line)
		b.WriteString("\033[K")
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	b.WriteString("\033[J")
	_, _ = io.WriteString(t.w, b.String())
}
