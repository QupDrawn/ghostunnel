package main

// tunnelchecks.go is the tunnel member's surface (observers/README, "About
// ghostunnel"): the mTLS data path as ghostunnel's own trace under gt/
// records it. The rules over the trace are surface_tunnel.go, which every
// member carries; what is this member's alone is the operator's
// expectation of the listener, the backend target, the rule set and what
// the backend is handed ahead of each connection (the proxy protocol
// mode), the trace's own consistency across cycles (tracememory.go), the
// liveness of every boot's process (bootliveness.go), and the comparison
// of the other surfaces with what their owners published (surfaces.go).
// Every check reads the current boot through gtreader.go and fails closed.
// A trace that cannot be read, a current boot with no start line, or a
// connection whose lines do not add up is a finding, never a skip: a check
// that cannot run has not passed, and the heartbeat lists every identifier
// below as checked.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The tunnel member's own check identifiers (SPEC 15: constants of this
// member's own code). The surface's are in surface_tunnel.go.
const (
	// checkTraceReadable: gt/ lists, the current boot reads under every
	// rule of ringtrace/README 1.4, and it holds a start line. Subject: the
	// path relative to gt/ where reading stopped, with the line when there
	// is one; "gt" for the root itself.
	checkTraceReadable = "trace-readable"
	// checkListenerExpected: the start line's listener is the one this
	// member was told to expect. Listed only when an expectation is
	// configured. Subject: the listener the start line names.
	checkListenerExpected = "listener-expected"
	// checkACLExpected: the start line's acl is, as a set, the rule this
	// member was told to expect. Listed only when an expectation is
	// configured. Subject: the start line's list joined by commas, cut to
	// 256 bytes.
	checkACLExpected = "acl-expected"
	// checkTargetExpected: the start line's backend target is the one this
	// member was told to expect. Listed only when an expectation is
	// configured. Subject: the target the start line names.
	checkTargetExpected = "target-expected"
	// checkProxyProtocolExpected: the start line's proxy_protocol, what the
	// backend is handed ahead of each connection, is the mode this member
	// was told to expect, off when it was told nothing. Always listed: a
	// header the backend was not meant to receive (under tls-full, the
	// client's whole certificate) is a finding whether or not the
	// operator thought to say so. Subject: the mode the start line names.
	checkProxyProtocolExpected = "proxy-protocol-expected"
)

// The substance rules (substance.go) are the surface's too: listed with
// it through tunnelSurfaceIdentifiers, computed in Run beside the other
// surface rules, from the chains under gt/chains/, the CA bundles under
// gt/material/ and the policy file on disk.

// TunnelChecks is the tunnel member's LocalChecks.
type TunnelChecks struct {
	// ExpectListen, when set, is the listener address the start line must
	// name. Empty means no expectation and no listener-expected check.
	ExpectListen string
	// ExpectTarget, when set, is the backend target the start line must
	// name. Empty means no expectation and no target-expected check.
	ExpectTarget string
	// ExpectACL, when non-empty, is the set of rules the start line's acl
	// must equal. Empty means no expectation and no acl-expected check.
	ExpectACL []string
	// ExpectProxyProtocol is the proxy_protocol the start line must name,
	// one of gtProxyProtocols. Empty means off, not "no expectation": the
	// check is always listed, and a proxy that hands the backend a header
	// nobody expected fails it.
	ExpectProxyProtocol string
	// TickMaxAge is how old the newest tick may be (tick-fresh) and how
	// far back accept-loop looks. Zero means defaultTickMaxAge.
	TickMaxAge time.Duration
	// LifetimeMargin is the observer's margin over the lifetime cap
	// (ringtrace/README 1.2): the trace records whole seconds and a close
	// lands after the cap fires. Zero means defaultLifetimeMargin.
	LifetimeMargin time.Duration
	// ACLGrace is how long after an accepted handshake its acl line, and
	// after a denial its refused close, may still be missing before the
	// absence is a finding. Zero means defaultACLGrace.
	ACLGrace time.Duration
	// ProcRoot is where the kernel exposes each live process as <pid>/;
	// /proc on Linux, and meaningful only there (liveness_linux.go).
	ProcRoot string
	// Live reports whether a process is live. Nil selects the probe of
	// this build (platformLiveness); tests inject the process-table probe
	// over a synthetic table, or a failure.
	Live livenessProbe
}

// aclExpectedSubjectBytes bounds acl-expected's subject, the start line's
// list joined by commas.
const aclExpectedSubjectBytes = 256

// parseExpectACL is the value of -expect-acl as a set: comma-separated
// rules in the trace's own spelling, no spaces, each in the vocabulary
// (gtACLRuleValid); repeated entries are one. An empty value is no
// expectation. Anything else is refused, so that a rule the trace could
// never carry is refused at start rather than compared every cycle.
func parseExpectACL(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, rule := range strings.Split(value, ",") {
		if rule == "" {
			return nil, fmt.Errorf("expect-acl: empty entry in %q", value)
		}
		if strings.ContainsAny(rule, " \t\r\n") {
			return nil, fmt.Errorf("expect-acl: %q contains whitespace", rule)
		}
		if err := gtACLRuleValid(rule); err != nil {
			return nil, fmt.Errorf("expect-acl: %v", err)
		}
		if !seen[rule] {
			seen[rule] = true
			out = append(out, rule)
		}
	}
	sort.Strings(out)
	return out, nil
}

// parseExpectProxyProtocol is the value of -expect-proxy-protocol: one of
// the start line's modes in the trace's own spelling (gtProxyProtocols),
// or empty, which is off. Anything else is refused at start, so a mode the
// trace could never carry is not compared every cycle.
func parseExpectProxyProtocol(value string) (string, error) {
	if value == "" {
		return "off", nil
	}
	for _, mode := range gtProxyProtocols {
		if value == mode {
			return value, nil
		}
	}
	return "", fmt.Errorf("expect-proxy-protocol: %q is not one of %v (empty means off)", value, gtProxyProtocols)
}

// expectedProxyProtocol is the mode the start line must name: the
// expectation as parsed, off when none was given.
func (c TunnelChecks) expectedProxyProtocol() string {
	if c.ExpectProxyProtocol == "" {
		return "off"
	}
	return c.ExpectProxyProtocol
}

// aclSetEqual reports whether two lists hold the same entries, whatever their
// order or repetition.
func aclSetEqual(a, b []string) bool {
	as := map[string]bool{}
	for _, s := range a {
		as[s] = true
	}
	bs := map[string]bool{}
	for _, s := range b {
		bs[s] = true
	}
	if len(as) != len(bs) {
		return false
	}
	for s := range as {
		if !bs[s] {
			return false
		}
	}
	return true
}

// Identifiers lists what Run may report about this member's own world, in
// evaluation order.
func (c TunnelChecks) Identifiers() []string {
	ids := []string{checkTraceReadable}
	ids = append(ids, tunnelSurfaceIdentifiers...)
	if c.ExpectListen != "" {
		ids = append(ids, checkListenerExpected)
	}
	if c.ExpectTarget != "" {
		ids = append(ids, checkTargetExpected)
	}
	if len(c.ExpectACL) > 0 {
		ids = append(ids, checkACLExpected)
	}
	ids = append(ids, checkProxyProtocolExpected)
	return append(ids, checkTickFresh, checkTraceConsistent, checkBootAmbiguous, checkBootEnded)
}

// RingIdentifiers lists what Run may report about the other members: the
// admin and material surfaces, judged here and compared with what their
// owners published.
func (c TunnelChecks) RingIdentifiers() []string {
	return surfaceRingIdentifiers(surfaceTunnel)
}

func (c TunnelChecks) margins() surfaceMargins {
	return surfaceMargins{LifetimeMargin: c.LifetimeMargin, ACLGrace: c.ACLGrace, TickMaxAge: c.TickMaxAge}
}

// allFail is what an unreadable trace yields for the checks over the
// current boot: every one fails because none could run (tick-fresh among
// them: no reference to judge by), and trace-readable says where.
// trace-consistent, boot-ambiguous and boot-ended are not among them; they
// are judged separately.
func (c TunnelChecks) allFail(subject string) []Finding {
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
func (c TunnelChecks) Run(cfg *Config, st *State, peers map[string]PeerView) []Finding {
	boot, listing, err := traceReadCurrent(st, cfg.TracesRoot)
	readable := err == nil && len(boot.Records) > 0 && boot.Records[0].Start != nil
	var out []Finding
	switch {
	case err != nil:
		out = c.allFail(gtSubject(err))
	case !readable:
		out = c.allFail(gtBootName(boot.Number))
	default:
		out = tunnelSurfaceFindings(boot, cfg.Now, c.LifetimeMargin, c.ACLGrace, c.TickMaxAge)
		out = append(out, substanceFindings(boot, substanceJudgeFor(cfg, st))...)
		start := boot.Records[0].Start
		if c.ExpectListen != "" && start.Config.Listen != c.ExpectListen {
			out = append(out, Finding{Check: checkListenerExpected, Subject: start.Config.Listen})
		}
		if c.ExpectTarget != "" && start.Config.Target != c.ExpectTarget {
			out = append(out, Finding{Check: checkTargetExpected, Subject: start.Config.Target})
		}
		if len(c.ExpectACL) > 0 && !aclSetEqual(start.Config.ACL, c.ExpectACL) {
			out = append(out, Finding{Check: checkACLExpected, Subject: boundBytes(strings.Join(start.Config.ACL, ","), aclExpectedSubjectBytes)})
		}
		if start.Config.ProxyProtocol != c.expectedProxyProtocol() {
			out = append(out, Finding{Check: checkProxyProtocolExpected, Subject: start.Config.ProxyProtocol})
		}
		out = append(out, tickFreshFindings(boot, cfg.Now, c.TickMaxAge)...)
	}
	live := c.Live
	if live == nil {
		live = platformLiveness(c.ProcRoot)
	}
	if err != nil {
		out = append(out, traceConsistentUnread()...)
		out = append(out, bootAmbiguousFindings(cfg.TracesRoot, listing, live)...)
	} else {
		previous := st.TraceBoot
		out = append(out, traceConsistentFindings(st, boot)...)
		out = append(out, bootAmbiguousFindings(cfg.TracesRoot, listing, live)...)
		out = append(out, bootEndedFindings(st, cfg.TracesRoot, previous, boot, cfg.Now, c.TickMaxAge)...)
	}
	out = append(out, surfaceDisagreements(surfaceTunnel, boot, readable, cfg.Now, c.margins(), substanceJudgeFor(cfg, st), peers)...)
	return out
}
