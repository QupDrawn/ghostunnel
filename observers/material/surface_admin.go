package main

// surface_admin.go is the admin surface as the proxy's own trace records it
// (observers/README, "About ghostunnel"): the checks over the status and
// admin HTTP surface that need nothing but the current boot. The admin
// member runs them as its own (adminchecks.go); every other member runs
// them too, from its own byte-identical copy of this file, and compares
// what it computes with what the admin member published (surfaces.go, SPEC
// 14.3). The process command line and the process itself are not here:
// they are read from the operating system, by the admin member alone.
//
// Nothing here opens a socket. The status listener is judged from the
// address the start line records, not by connecting to it; what the status
// surface serves is judged from what the start line says of it.

import (
	"net"
	"strings"
)

// The admin surface's check identifiers (SPEC 15: constants of the
// members' own code, spelled the same in every copy).
const (
	// checkStatusListenerBound: the start line's status_listen is null,
	// names a loopback address, or status_client_cert is true. A unix,
	// systemd or launchd socket, an unspecified host, or an address that
	// does not parse is none of these. Subject: the address.
	checkStatusListenerBound = "status-listener-bound"
	// checkPprofCmdlineRedacted: when a status surface is served, the
	// start line says /debug/pprof/cmdline redacts every argument value
	// (config.pprof_cmdline_redacted). Subject: null.
	checkPprofCmdlineRedacted = "pprof-cmdline-redacted"
	// checkShutdownAuthorized: when a status surface is served, the start
	// line says /_shutdown acts only for a verified client certificate
	// (config.shutdown_requires_client_cert); and every shutdown line in
	// the current boot was authorized, one that came over the status
	// endpoint naming the peer that asked. Subject: "not-gated", the
	// source, or "<source>:no-peer".
	checkShutdownAuthorized = "shutdown-authorized"
	// checkStatusListenerUp: no refusal line of the current boot names the
	// status listener. The proxy writes one, once, when the listener's
	// Serve returns an error, refuses to serve from then on until restart,
	// and nothing else in the trace says why; the line stands for the rest
	// of the boot, so the finding does too. Subject: the line's error
	// text, cut to 64 bytes on a rune boundary, once per distinct text.
	checkStatusListenerUp = "status-listener-up"
)

// statusListenerSubjectBytes bounds status-listener-up's subject, the
// error text, as accept-loop bounds its own.
const statusListenerSubjectBytes = 64

// adminSurfaceIdentifiers lists the surface's checks in evaluation order.
var adminSurfaceIdentifiers = []string{checkStatusListenerBound, checkPprofCmdlineRedacted, checkShutdownAuthorized, checkStatusListenerUp}

// adminSurfaceFindings judges a readable current boot with a start line.
func adminSurfaceFindings(boot *gtBoot) []Finding {
	conf := &boot.Records[0].Start.Config
	var out []Finding
	fail := func(check string, subject string) {
		out = append(out, Finding{Check: check, Subject: subject})
	}

	// The status surface, when there is one.
	if sl := conf.StatusListen; sl != nil {
		if !conf.StatusClientCert && !isLoopbackListen(*sl) {
			fail(checkStatusListenerBound, *sl)
		}
		if !conf.PprofCmdlineRedacted {
			fail(checkPprofCmdlineRedacted, "")
		}
		if !conf.ShutdownRequiresClientCert {
			fail(checkShutdownAuthorized, "not-gated")
		}
	}

	// One walk: the shutdown requests, and the status listener's death,
	// the one line that says why the proxy refuses, which it writes once
	// and which stands for the boot. The shutdown findings come first, in
	// the order of their lines, then the listener's.
	var down []Finding
	seen := map[string]bool{}
	for i := range boot.Records {
		rec := &boot.Records[i]
		if s := rec.Shutdown; s != nil {
			if !s.Authorized {
				fail(checkShutdownAuthorized, s.Source)
			}
			if s.Source == "status-endpoint" && s.Peer == nil {
				fail(checkShutdownAuthorized, s.Source+":no-peer")
			}
		}
		if r := rec.Refusal; r != nil && r.Source == "status-listener" {
			subject := boundBytes(r.Error, statusListenerSubjectBytes)
			if !seen[subject] {
				seen[subject] = true
				down = append(down, Finding{Check: checkStatusListenerUp, Subject: subject})
			}
		}
	}
	return append(out, down...)
}

// isLoopbackListen reports whether a status address of the forms the flag
// accepts ([http(s)://]HOST:PORT, unix:PATH, systemd:NAME, launchd:NAME)
// binds a loopback interface. Only HOST:PORT with a loopback host is;
// everything else, including an address that does not parse, is not.
func isLoopbackListen(addr string) bool {
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "https://"), "http://")
	for _, pre := range []string{"unix:", "systemd:", "launchd:"} {
		if strings.HasPrefix(addr, pre) {
			return false
		}
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
