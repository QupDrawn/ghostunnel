// Command box runs the benchmark on a remote host over ssh, brings the
// report back into this tool's work/results folder, and prints it the way
// ringstatus prints the ring: a title line, one verdict badge, columned
// tables. -host is required; every other flag has a default.
//
//	go -C bench run ./box -host H                  run there (end to end only), fetch, render
//	go -C bench run ./box -host H -quick           the -quick run
//	go -C bench run ./box -host H -gobench         include the trees' own Go benchmarks (slow)
//	go -C bench run ./box -host H -latest          fetch and render the host's newest report, no run
//	go -C bench run ./box -host H -fetch STAMP     fetch and render one report by its stamp
//	go -C bench run ./box -render FILE             render a report already on this machine, no ssh
//
// The remote host must already hold a clone of the repository (-remote-repo)
// with this tool under it (-remote-bench, default <remote-repo>/bench), Go
// on its PATH or under /usr/local/go, and a work directory on a disk with
// fast fsync (-remote-work; see README.md). Every report fetched lands here
// as work/results/box-<stamp>.txt, so this machine's own runs and the remote
// host's sit side by side and are told apart by the prefix.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type options struct {
	host, user, key         string
	remoteRepo, remoteBench string
	remoteWork              string
	base, fork              string
	quick, gobench          bool
	backend, order          string
	forkArgs                string
	count                   int
	latest, fetch, render   string
	noColor                 bool
}

func sourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(filepath.Dir(file)) // bench/
}

func main() {
	var o options
	flag.StringVar(&o.host, "host", "", "the remote host to run on (address or ssh alias); required unless -render")
	flag.StringVar(&o.user, "user", "ubuntu", "ssh user on the remote host")
	flag.StringVar(&o.key, "key", "", "ssh private key file (default: ssh's own key selection)")
	flag.StringVar(&o.remoteRepo, "remote-repo", "~/ghostunnel", "the repository clone on the remote host (holds both refs)")
	flag.StringVar(&o.remoteBench, "remote-bench", "", "this tool's directory on the remote host (default: <remote-repo>/bench)")
	flag.StringVar(&o.remoteWork, "remote-work", "", "the bench's -work on the remote host; put it on a disk with fast fsync (default: the bench's own, work/ under -remote-bench)")
	flag.StringVar(&o.base, "base", "", "the bench's -base (default: its merge-base of the fork ref and origin/master)")
	flag.StringVar(&o.fork, "fork", "portal", "the bench's -fork")
	flag.BoolVar(&o.quick, "quick", false, "the bench's -quick (count 2, conns 100, bulk 16)")
	flag.BoolVar(&o.gobench, "gobench", false, "include the trees' own Go benchmarks (adds many minutes)")
	flag.IntVar(&o.count, "count", 0, "the bench's -count (0: its default)")
	flag.StringVar(&o.backend, "backend", "", "the bench's -backend: host:port of an echo started on another host with -serve-echo, reachable from the remote host (empty: a loopback echo on the remote host)")
	flag.StringVar(&o.order, "order", "", "the bench's -order: abba (interleaved, the default) or sequential")
	flag.StringVar(&o.forkArgs, "fork-args", "", "the bench's -fork-args: extra flags for the fork proxy only")
	var latest bool
	flag.BoolVar(&latest, "latest", false, "fetch and render the remote host's newest report instead of running")
	flag.StringVar(&o.fetch, "fetch", "", "fetch and render the report with this stamp instead of running")
	flag.StringVar(&o.render, "render", "", "render this local report file; no ssh")
	flag.BoolVar(&o.noColor, "no-color", false, "plain text")
	flag.Parse()
	if latest {
		o.latest = "latest"
	}
	if o.remoteBench == "" {
		o.remoteBench = o.remoteRepo + "/bench"
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		o.noColor = true
	}
	enableVirtualTerminal(os.Stdout)

	if o.render == "" && o.host == "" {
		fmt.Fprintln(os.Stderr, "box: -host is required: the remote host to run on, as an address or an ssh alias (or -render FILE to print a report already here)")
		os.Exit(2)
	}
	if err := run(&o); err != nil {
		fmt.Fprintf(os.Stderr, "box: %v\n", err)
		os.Exit(1)
	}
}

func progress(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[box %s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func run(o *options) error {
	var local string
	switch {
	case o.render != "":
		local = o.render
	default:
		stamp := o.fetch
		if o.latest != "" {
			stamp = ""
		}
		if o.fetch == "" && o.latest == "" {
			s, err := runRemote(o)
			if err != nil {
				return err
			}
			stamp = s
		}
		if stamp == "" {
			s, err := newestRemoteStamp(o)
			if err != nil {
				return err
			}
			stamp = s
		}
		p, err := fetchReport(o, stamp)
		if err != nil {
			return err
		}
		local = p
	}
	text, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	r := parseReport(string(text))
	r.file = local
	fmt.Print(strings.Join(renderLines(r, time.Now(), o.noColor), "\n") + "\n")
	return nil
}

// ---- the remote host --------------------------------------------------------

// keyArgs is the -i option when a key file was given; with none, ssh and
// scp pick the key themselves (agent, ssh config, the default names).
func (o *options) keyArgs() []string {
	if o.key == "" {
		return nil
	}
	return []string{"-i", o.key}
}

func (o *options) ssh(args ...string) *exec.Cmd {
	base := append(o.keyArgs(), "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30")
	return exec.Command("ssh", append(append(base, o.user+"@"+o.host), args...)...)
}

var reReportWritten = regexp.MustCompile(`report written to (\S+/results/(\d{8}-\d{6})\.txt)`)

// runRemote runs the bench on the remote host, relaying its progress lines
// here, and returns the stamp of the report it wrote. The remote command
// runs in the foreground of this ssh session; a dropped session kills it,
// which is what an operator watching the run wants, and the -fetch and
// -latest modes are there for the case where it did not.
func runRemote(o *options) (string, error) {
	args := []string{"-repo", o.remoteRepo, "-fork", o.fork}
	if o.base != "" {
		args = append(args, "-base", o.base)
	}
	if o.remoteWork != "" {
		args = append(args, "-work", o.remoteWork)
	}
	if !o.gobench {
		args = append(args, "-skip-gobench")
	}
	if o.quick {
		args = append(args, "-quick")
	}
	if o.count > 0 {
		args = append(args, "-count", strconv.Itoa(o.count))
	}
	if o.backend != "" {
		args = append(args, "-backend", o.backend)
	}
	if o.order != "" {
		args = append(args, "-order", o.order)
	}
	if o.forkArgs != "" {
		args = append(args, "-fork-args", "'"+o.forkArgs+"'")
	}
	remote := "cd " + o.remoteBench + " && export PATH=$PATH:/usr/local/go/bin && go run . " + strings.Join(args, " ")
	progress("running on %s: %s", o.host, remote)
	cmd := o.ssh(remote)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	cmd.Stdout = io.Discard // the report itself; it is fetched as a file below
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("ssh: %w", err)
	}
	var stamp string
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintln(os.Stderr, paint("  "+line, "grey", o.noColor))
		if m := reReportWritten.FindStringSubmatch(line); m != nil {
			stamp = m[2]
		}
	}
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("the run on %s failed: %w", o.host, err)
	}
	if stamp == "" {
		return "", errors.New("the run ended without reporting a result file")
	}
	return stamp, nil
}

// resultsDir is where the bench on the remote host writes its reports:
// under -remote-work when given, else under the bench's own default.
func (o *options) resultsDir() string {
	if o.remoteWork != "" {
		return o.remoteWork + "/results"
	}
	return o.remoteBench + "/work/results"
}

func newestRemoteStamp(o *options) (string, error) {
	out, err := o.ssh("ls " + o.resultsDir()).Output()
	if err != nil {
		return "", fmt.Errorf("listing the results on %s: %w", o.host, err)
	}
	var stamps []string
	for _, name := range strings.Fields(string(out)) {
		if m := regexp.MustCompile(`^(\d{8}-\d{6})\.txt$`).FindStringSubmatch(name); m != nil {
			stamps = append(stamps, m[1])
		}
	}
	if len(stamps) == 0 {
		return "", fmt.Errorf("no reports on %s under %s", o.host, o.resultsDir())
	}
	sort.Strings(stamps)
	return stamps[len(stamps)-1], nil
}

// fetchReport copies one report (and its raw gobench files, when the run
// produced them) into work/results here, prefixed box-.
func fetchReport(o *options, stamp string) (string, error) {
	results := filepath.Join(sourceDir(), "work", "results")
	if err := os.MkdirAll(results, 0o755); err != nil {
		return "", err
	}
	remote := o.resultsDir() + "/" + stamp
	names := []string{".txt", "-base-gobench.txt", "-fork-gobench.txt"}
	var local string
	for i, suffix := range names {
		dst := filepath.Join(results, "box-"+stamp+suffix)
		scpArgs := append([]string{"-q"}, o.keyArgs()...)
		scpArgs = append(scpArgs, "-o", "StrictHostKeyChecking=accept-new",
			o.user+"@"+o.host+":"+remote+suffix, dst)
		cmd := exec.Command("scp", scpArgs...)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if i == 0 {
				return "", fmt.Errorf("fetching %s: %w\n%s", remote+suffix, err, strings.TrimSpace(stderr.String()))
			}
			continue // no gobench files for a -skip-gobench run; nothing to say
		}
		if i == 0 {
			local = dst
		}
	}
	progress("report fetched to %s", local)
	return local, nil
}

// ---- the report ---------------------------------------------------------------

type row struct {
	label      string
	base, fork string // as printed; "-" when absent
	delta      *float64
}

type report struct {
	file                            string
	started, finished, took, host   string
	baseHash, baseDate, baseSubject string
	forkRef, forkHash, forkDate     string
	forkSubject, flags, work, fsync string
	backend                         string
	forkArgs, forkPool              string
	warning                         bool
	e2e, gobench                    []row
	e2eSkipped, goSkipped           bool
	trace                           string
}

var (
	reDelta = regexp.MustCompile(`^([+-]?\d+(?:\.\d+)?)%$`)
	reHash  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func parseReport(text string) *report {
	r := &report{}
	section := ""
	var last string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "Go benchmarks"):
			section = "go"
			continue
		case strings.HasPrefix(line, "End to end"):
			section = "e2e"
			continue
		case strings.HasPrefix(line, "Caveats"):
			section = "caveats"
			continue
		}
		key, val, _ := strings.Cut(line, " ")
		val = strings.TrimSpace(val)
		if section == "" {
			switch key {
			case "started":
				r.started = val
			case "finished":
				r.finished, r.took, _ = strings.Cut(val, " ")
				r.took = strings.Trim(r.took, "()")
			case "host":
				r.host = val
			case "base":
				r.baseHash = val
			case "fork":
				r.forkRef = val
			case "flags":
				r.flags = val
			case "work":
				r.work = val
			case "fsync":
				r.fsync = val
			case "backend":
				r.backend = val
			case "fork-args":
				r.forkArgs = val
			case "fork-pool":
				r.forkPool = val
			case "WARNING":
				r.warning = true
			case "":
				// A continuation line: the hash/date under base or fork, or a subject.
				f := strings.Fields(val)
				switch {
				case len(f) >= 2 && reHash.MatchString(f[0]) && last == "base":
					r.baseDate = f[1]
				case len(f) >= 2 && reHash.MatchString(f[0]) && last == "fork":
					r.forkHash, r.forkDate = f[0], f[1]
				case last == "base" && r.baseDate != "" && r.baseSubject == "":
					r.baseSubject = val
				case last == "fork" && r.forkDate != "" && r.forkSubject == "":
					r.forkSubject = val
				}
				continue
			}
			if key != "" {
				last = key
			}
			continue
		}
		if section == "e2e" && strings.HasPrefix(line, "fork trace after the run:") {
			r.trace = strings.TrimPrefix(line, "fork trace after the run: ")
			continue
		}
		if strings.HasPrefix(line, "skipped") {
			if section == "go" {
				r.goSkipped = true
			} else if section == "e2e" {
				r.e2eSkipped = true
			}
			continue
		}
		if !strings.Contains(line, " | ") || strings.HasPrefix(line, "benchmark ") || strings.HasPrefix(line, "measurement ") {
			continue
		}
		cells := strings.Split(line, " | ")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) < 4 {
			continue
		}
		rw := row{label: cells[0], base: cells[1], fork: cells[2]}
		if m := reDelta.FindStringSubmatch(cells[3]); m != nil {
			d, _ := strconv.ParseFloat(m[1], 64)
			rw.delta = &d
		}
		if section == "go" {
			r.gobench = append(r.gobench, rw)
		} else {
			r.e2e = append(r.e2e, rw)
		}
	}
	return r
}

// ---- painting, as ringstatus does it ----------------------------------------------

var colours = map[string]string{
	"green": "0;32", "red": "1;31", "amber": "0;33",
	"grey": "0;90", "bold": "1", "cyan": "0;36",
}

func paint(text, colour string, noColor bool) string {
	if noColor {
		return text
	}
	code, ok := colours[colour]
	if !ok {
		code = "0"
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

var reEscape = regexp.MustCompile("\033\\[[0-9;]*m")

func visibleWidth(s string) int { return len(reEscape.ReplaceAllString(s, "")) }

func pad(text string, width int) string {
	n := width - visibleWidth(text)
	if n <= 0 {
		return text
	}
	return text + strings.Repeat(" ", n)
}

func lpad(text string, width int) string {
	n := width - visibleWidth(text)
	if n <= 0 {
		return text
	}
	return strings.Repeat(" ", n) + text
}

const timestampLayout = "2006-01-02T15:04:05Z"

// lowerIsBetter says whether a smaller number is the better one for a row:
// every latency, every ns/op; a rate (connections/s, MiB/s) is the other way.
func lowerIsBetter(label string) bool {
	l := strings.ToLower(label)
	return !(strings.Contains(l, "connections/s") || strings.Contains(l, "mib/s"))
}

// deltaColour: the fork better by more than the noise is green, worse by more
// than the noise red, within it grey. The noise band is the caveat's own: the
// median of a small -count moves a few percent between runs.
const noiseBand = 3.0

func deltaColour(d float64, lower bool) string {
	better := d < 0
	if !lower {
		better = d > 0
	}
	switch {
	case d > -noiseBand && d < noiseBand:
		return "grey"
	case better:
		return "green"
	default:
		return "red"
	}
}

func deltaCell(d *float64, label string, noColor bool) string {
	if d == nil {
		return paint("-", "grey", noColor)
	}
	return paint(fmt.Sprintf("%+.1f%%", *d), deltaColour(*d, lowerIsBetter(label)), noColor)
}

// remoteBackend reads the report's backend line: "remote host:port ..." as
// the bench writes it now, or the first form, "host:port (remote echo ...)".
func remoteBackend(line string) bool {
	return strings.HasPrefix(line, "remote ") || strings.Contains(line, "remote echo")
}

func short(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

func renderLines(r *report, now time.Time, noColor bool) []string {
	c := func(text, colour string) string { return paint(text, colour, noColor) }
	var L []string

	L = append(L, "")
	L = append(L, "  "+c("GHOSTUNNEL", "bold")+c("  ·  benchmark, base vs fork", "grey")+
		strings.Repeat(" ", 16)+c(now.UTC().Format(timestampLayout), "grey"))
	L = append(L, "")

	// --- the verdict ---
	//
	// From the two numbers that decide it: the sequential p50 (what one
	// connection pays for the ring) and the 16-way rate (what the host does
	// under load). Both inside the noise band is a tie; either one worse
	// by more than the band is the fork slower; both better is faster.
	find := func(label string) *float64 {
		for _, rw := range r.e2e {
			if rw.label == label {
				return rw.delta
			}
		}
		return nil
	}
	p50, conc := find("churn: p50 ms"), find("concurrent x16: connections/s")
	switch {
	case r.e2eSkipped || p50 == nil || conc == nil:
		L = append(L, "  "+c(" NO VERDICT ", "amber")+"  "+c("no end-to-end measurement in this report", "bold"))
	case r.warning:
		L = append(L, "  "+c(" DISK BOUND ", "red")+"  "+
			c("the work volume's fsync is above the warning line; these numbers measure the disk", "bold"))
	// Worse than the band on either axis is slower; better than the band
	// on either axis while not worse than it on the other is faster.
	case *p50 > noiseBand || *conc < -noiseBand:
		L = append(L, "  "+c(" FORK SLOWER ", "red")+"  "+
			c(fmt.Sprintf("one connection %+.1f%% p50, sixteen at once %+.1f%% connections/s", *p50, *conc), "bold"))
	case *p50 < -noiseBand || *conc > noiseBand:
		L = append(L, "  "+c(" FORK FASTER ", "green")+"  "+
			c(fmt.Sprintf("one connection %+.1f%% p50, sixteen at once %+.1f%% connections/s", *p50, *conc), "bold"))
	default:
		L = append(L, "  "+c(" EVEN ", "green")+"  "+
			c(fmt.Sprintf("one connection %+.1f%% p50, sixteen at once %+.1f%% connections/s, inside the %.0f%% noise band", *p50, *conc, noiseBand), "bold"))
	}
	where := "loopback backend"
	if remoteBackend(r.backend) {
		where = "remote backend"
	}
	L = append(L, "  "+c(fmt.Sprintf("base %s · fork %s (%s) · %s · %s · %s", short(r.baseHash), short(r.forkHash), r.forkRef, r.host, r.flags, where), "grey"))
	L = append(L, "")

	// --- the run ---
	kv := func(k, v string) string { return "  " + c(pad(k, 10), "grey") + v }
	L = append(L, kv("fork", c(r.forkSubject, "bold")+c("  "+r.forkDate, "grey")))
	L = append(L, kv("base", r.baseSubject+c("  "+r.baseDate, "grey")))
	L = append(L, kv("ran", r.started+c("  took "+r.took, "grey")))
	if r.forkArgs != "" {
		L = append(L, kv("fork-args", c(r.forkArgs, "amber")))
	}
	if r.forkPool != "" {
		colour := "grey"
		if !strings.HasPrefix(r.forkPool, "none") {
			colour = "cyan"
		}
		L = append(L, kv("fork pool", c(r.forkPool, colour)))
	}
	switch {
	case remoteBackend(r.backend):
		L = append(L, kv("backend", c("REMOTE", "cyan")+"  "+strings.TrimPrefix(r.backend, "remote ")))
	case r.backend != "":
		L = append(L, kv("backend", c("LOOPBACK", "grey")+"  "+strings.TrimPrefix(r.backend, "loopback ")))
	default:
		// A report from before the header carried the line: the echo
		// was the bench's own, on the host that ran it.
		L = append(L, kv("backend", c("LOOPBACK", "grey")+"  "+c("an echo in the bench's process on the host that ran it", "grey")))
	}
	if r.work != "" {
		L = append(L, kv("work", r.work))
	}
	if r.fsync != "" {
		colour := "green"
		if r.warning {
			colour = "red"
		}
		L = append(L, kv("fsync", c(r.fsync, colour)))
	}
	L = append(L, kv("report", c(r.file, "grey")))
	L = append(L, "")

	// --- end to end ---
	L = append(L, "  "+c(pad("END TO END", 32)+lpad("BASE", 10)+lpad("FORK", 10)+lpad("DELTA", 10), "grey"))
	if r.e2eSkipped {
		L = append(L, "  "+c("skipped", "grey"))
	}
	for _, rw := range r.e2e {
		L = append(L, "  "+pad(c(rw.label, "bold"), 32)+lpad(rw.base, 10)+lpad(rw.fork, 10)+lpad(deltaCell(rw.delta, rw.label, noColor), 10))
	}
	if r.trace != "" {
		L = append(L, "  "+c("fork trace: "+r.trace, "grey"))
	}
	L = append(L, "")

	// --- the Go benchmarks: the shared rows by delta, the fork-only ones counted ---
	L = append(L, "  "+c(pad("GO BENCHMARKS", 54)+lpad("BASE ns/op", 14)+lpad("FORK ns/op", 14)+lpad("DELTA", 10), "grey"))
	switch {
	case r.goSkipped:
		L = append(L, "  "+c("skipped", "grey"))
	case len(r.gobench) == 0:
		L = append(L, "  "+c("none in this report", "grey"))
	default:
		var shared, forkOnly, baseOnly []row
		for _, rw := range r.gobench {
			switch {
			case strings.HasSuffix(rw.label, "(fork only)"):
				forkOnly = append(forkOnly, rw)
			case strings.HasSuffix(rw.label, "(base only)"):
				baseOnly = append(baseOnly, rw)
			default:
				shared = append(shared, rw)
			}
		}
		sort.SliceStable(shared, func(i, j int) bool {
			di, dj := 0.0, 0.0
			if shared[i].delta != nil {
				di = *shared[i].delta
			}
			if shared[j].delta != nil {
				dj = *shared[j].delta
			}
			return di < dj
		})
		for _, rw := range shared {
			L = append(L, "  "+pad(rw.label, 54)+lpad(rw.base, 14)+lpad(rw.fork, 14)+lpad(deltaCell(rw.delta, rw.label, noColor), 10))
		}
		// The ring's own benchmarks have no base column; the two that
		// matter most are shown, the rest counted.
		for _, rw := range forkOnly {
			if strings.HasPrefix(rw.label, "ghostunnel.BenchmarkRingConnPath") || strings.HasPrefix(rw.label, "ringtrace.BenchmarkEmit") {
				L = append(L, "  "+pad(c(rw.label, "grey"), 54)+lpad("-", 14)+lpad(rw.fork, 14)+lpad(c("-", "grey"), 10))
			}
		}
		L = append(L, "  "+c(fmt.Sprintf("%d shared · %d fork only · %d base only; the full table is in the report", len(shared), len(forkOnly), len(baseOnly)), "grey"))
	}
	L = append(L, "")
	L = append(L, "  "+c("green: the fork better by more than the noise band, red: worse, grey: within it", "grey"))
	return L
}
