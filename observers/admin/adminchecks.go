package main

// adminchecks.go is the admin member's surface (observers/README, "About
// ghostunnel"): the status and admin HTTP surface as ghostunnel's own trace
// under gt/ records it, and the process the start line names as the
// operating system exposes it. The rules over the trace are
// surface_admin.go, which every member carries; what is this member's
// alone is the process: its command line (cmdline_*.go) and that it is the
// process that wrote the start line (procstart_*.go), plus the trace's own
// consistency across cycles (tracememory.go), the liveness of every boot's
// process (bootliveness.go), and the comparison of the other surfaces with
// what their owners published (surfaces.go). Every check reads the current
// boot through gtreader.go and fails closed: a trace that cannot be read, a
// current boot with no start line, or a process that cannot be read is a
// finding, never a skip. A check that cannot run has not passed, and the
// heartbeat lists every identifier below as checked.
//
// Reading the proxy's command line and start time is this member's own
// competence, with no opt-in on any OS: the readers are selected by build
// tag (cmdline_linux.go and procstart_linux.go read /proc, the _windows
// files read the process through its handle, the _other files fail closed
// naming the OS), and each returns the same shape for the same rules.
//
// Nothing here opens a socket.

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The admin member's own check identifiers (SPEC 15: constants of this
// member's own code). The surface's are in surface_admin.go.
const (
	// checkTraceReadable: gt/ lists, the current boot reads under every
	// rule of ringtrace/README 1.4, and it holds a start line. Subject: the
	// path relative to gt/ where reading stopped, with the line when there
	// is one; "gt" for the root itself.
	checkTraceReadable = "trace-readable"
	// checkCmdlineNoSecret: the command line of the process the start line
	// names, read by the reader this build selected (cmdline_*.go), carries
	// no --storepass or --pkcs11-pin value and no URL with credentials; a
	// command line that cannot be read has not been checked. Subject: the
	// flag, or "url-credentials"; "pid:<pid>" when the process is gone or
	// its command line is empty; "unsupported-os:<GOOS>" on a build with
	// no reader; and on Windows "pid:<pid>:access-denied",
	// "pid:<pid>:bitness-mismatch" or "pid:<pid>:unreadable" for a process
	// this observer may not open, one of another word size, or one whose
	// parameter block cannot be read.
	checkCmdlineNoSecret = "cmdline-carries-no-secret"
)

// cmdlineReader returns the argv of the process pid as the operating
// system exposes it, or an error. An error that is a *cmdlineError carries
// its own bounded subject; any other names the pid.
type cmdlineReader func(pid int64) ([]string, error)

// cmdlineError is a reader's failure with the subject the finding gets.
type cmdlineError struct {
	Subject string
	Err     error
}

func (e *cmdlineError) Error() string { return e.Subject + ": " + e.Err.Error() }
func (e *cmdlineError) Unwrap() error { return e.Err }

// cmdlineSubject is the finding subject for a reader's error.
func cmdlineSubject(err error, pid int64) string {
	var e *cmdlineError
	if errors.As(err, &e) {
		return e.Subject
	}
	return "pid:" + strconv.FormatInt(pid, 10)
}

// unsupportedOSCmdline is the reader of a build with no facility for
// reading another process's command line: every read fails closed naming
// the OS, so the check fails and the heartbeat says why.
func unsupportedOSCmdline(goos string) cmdlineReader {
	return func(int64) ([]string, error) {
		return nil, &cmdlineError{Subject: "unsupported-os:" + goos, Err: errors.New("no command-line reader for this OS")}
	}
}

// secretFlags are ghostunnel's flags whose value is a secret. Both have an
// environment form (KEYSTORE_PASS, PKCS11_PIN) that leaves nothing on the
// command line.
var secretFlags = []string{"--storepass", "--pkcs11-pin"}

// AdminChecks is the admin member's LocalChecks.
type AdminChecks struct {
	// ProcRoot is where the kernel exposes each process as <pid>/
	// (cmdline, stat) and the boot time as stat; /proc on Linux, and
	// meaningful only there. Empty reads nothing there and fails.
	ProcRoot string
	// Cmdline reads a process's command line. Nil selects the reader of
	// this build (platformCmdline); tests inject the /proc-format reader
	// over a synthetic table, or a failure.
	Cmdline cmdlineReader
	// StartTime reads when a process started. Nil selects the reader of
	// this build (platformStartTime); tests inject the /proc-format
	// reader over a synthetic table, or a failure.
	StartTime startTimeReader
	// Live reports whether a process is live. Nil selects the probe of
	// this build (platformLiveness); tests inject the process-table probe
	// over a synthetic table, or a failure.
	Live livenessProbe
	// TunnelMargins are the tunnel surface's values this member judges
	// that surface with, which must be the tunnel member's own; its
	// TickMaxAge is also this member's own tick-fresh age (-tick-max-age,
	// one value on every member).
	TunnelMargins surfaceMargins
}

// Identifiers lists what Run may report about this member's own world, in
// evaluation order.
func (c AdminChecks) Identifiers() []string {
	ids := []string{checkTraceReadable}
	ids = append(ids, adminSurfaceIdentifiers...)
	return append(ids, checkCmdlineNoSecret, checkProxyProcessAlive, checkTickFresh, checkTraceConsistent, checkBootAmbiguous, checkBootEnded)
}

// RingIdentifiers lists what Run may report about the other members: the
// tunnel and material surfaces, judged here and compared with what their
// owners published.
func (c AdminChecks) RingIdentifiers() []string {
	return surfaceRingIdentifiers(surfaceAdmin)
}

// allFail is what an unreadable trace yields for the checks over the
// current boot: every one fails because none could run (tick-fresh among
// them: no reference to judge by), and trace-readable says where.
// trace-consistent, boot-ambiguous and boot-ended are not among them; they
// are judged separately.
func (c AdminChecks) allFail(subject string) []Finding {
	out := []Finding{{Check: checkTraceReadable, Subject: subject}}
	for _, id := range c.Identifiers() {
		if id != checkTraceReadable && id != checkTraceConsistent && id != checkBootAmbiguous && id != checkBootEnded {
			out = append(out, Finding{Check: id})
		}
	}
	return out
}

// Run reads the current boot and judges it, then the trace's consistency
// with what was read last cycle, every boot's process, and the other
// surfaces against their owners' accounts.
func (c AdminChecks) Run(cfg *Config, st *State, peers map[string]PeerView) []Finding {
	boot, listing, err := traceReadCurrent(st, cfg.TracesRoot)
	readable := err == nil && len(boot.Records) > 0 && boot.Records[0].Start != nil
	var out []Finding
	switch {
	case err != nil:
		out = c.allFail(gtSubject(err))
	case !readable:
		out = c.allFail(gtBootName(boot.Number))
	default:
		out = adminSurfaceFindings(boot)
		// The process the start line names: its command line, and that
		// it is the process that wrote the line.
		start := boot.Records[0]
		for _, subject := range c.cmdlineSecrets(start.Start.PID) {
			out = append(out, Finding{Check: checkCmdlineNoSecret, Subject: subject})
		}
		for _, subject := range c.processAlive(start.Start.PID, start.At) {
			out = append(out, Finding{Check: checkProxyProcessAlive, Subject: subject})
		}
		out = append(out, tickFreshFindings(boot, cfg.Now, c.TunnelMargins.TickMaxAge)...)
	}
	live := c.Live
	if live == nil {
		live = platformLiveness(c.ProcRoot)
	}
	if err != nil {
		out = append(out, traceConsistentUnread()...)
		out = append(out, bootAmbiguousFindings(cfg.TracesRoot, listing, live, startLineMemo(st))...)
	} else {
		previous := st.TraceBoot
		out = append(out, traceConsistentFindings(st, boot)...)
		out = append(out, bootAmbiguousFindings(cfg.TracesRoot, listing, live, startLineMemo(st))...)
		out = append(out, bootEndedFindings(st, cfg.TracesRoot, previous, boot, cfg.Now, c.TunnelMargins.TickMaxAge)...)
	}
	out = append(out, surfaceDisagreements(surfaceAdmin, boot, readable, cfg.Now, c.TunnelMargins, substanceJudgeFor(cfg, st), peers)...)
	return out
}

// cmdlineSecrets reads the command line of pid through the reader and
// returns the subjects of what it finds wrong: each secret-bearing flag
// present with a value, a URL carrying credentials, or the reader's own
// subject when the command line cannot be read; "pid:<pid>" when it is
// empty (a process that is gone, or a zombie).
func (c AdminChecks) cmdlineSecrets(pid int64) []string {
	read := c.Cmdline
	if read == nil {
		read = platformCmdline(c.ProcRoot)
	}
	argv, err := read(pid)
	if err != nil {
		return []string{cmdlineSubject(err, pid)}
	}
	if len(argv) == 0 {
		return []string{"pid:" + strconv.FormatInt(pid, 10)}
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, arg := range argv {
		for _, flag := range secretFlags {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				add(flag)
			}
		}
		value := arg
		if i := strings.Index(arg, "="); i > 0 && strings.HasPrefix(arg, "--") {
			value = arg[i+1:]
		}
		if u, err := url.Parse(value); err == nil && u.Scheme != "" && u.Host != "" && u.User != nil {
			add("url-credentials")
		}
	}
	return out
}

// processAlive is proxy-process-alive over the reader this member holds
// (procstart.go).
func (c AdminChecks) processAlive(pid int64, at time.Time) []string {
	read := c.StartTime
	if read == nil {
		read = platformStartTime(c.ProcRoot)
	}
	return proxyProcessAliveSubjects(pid, at, read)
}
