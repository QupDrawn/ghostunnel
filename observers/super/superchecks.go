package main

// superchecks.go is the super member's local checks. super has no assigned
// ghostunnel surface (observers/README): it watches the other three
// members, and, since every member judges the proxy's trace for every
// surface (SPEC 14.3), it reads the trace too and compares what it computes
// for the tunnel, admin and material surfaces with what their owners
// published (surfaces.go), from its own copies of each surface's rules.
// It also keeps the trace consistent with what it read last cycle and
// judges its freshness by the proxy's tick line (tracememory.go). Every
// read of the trace goes through gtreader.go and fails closed: a trace
// that cannot be read is a finding, never a skip, and the heartbeat lists
// every identifier below as checked.

// The super member's own check identifiers (SPEC 15: constants of this
// member's own code).
const (
	// checkTraceReadable: gt/ lists, the current boot reads under every
	// rule of ringtrace/README 1.4, and it holds a start line. Subject: the
	// path relative to gt/ where reading stopped, with the line when there
	// is one; "gt" for the root itself.
	checkTraceReadable = "trace-readable"
)

// SuperChecks is the super member's LocalChecks.
type SuperChecks struct {
	// TunnelMargins are the tunnel surface's values this member judges
	// that surface with, which must be the tunnel member's own; its
	// TickMaxAge is also this member's own tick-fresh age (-tick-max-age,
	// one value on every member).
	TunnelMargins surfaceMargins
}

// Identifiers lists what Run may report about this member's own world, in
// evaluation order.
func (c SuperChecks) Identifiers() []string {
	return []string{checkTraceReadable, checkTickFresh, checkTraceConsistent, checkBootEnded}
}

// RingIdentifiers lists what Run may report about the other members: all
// three surfaces, judged here and compared with what their owners
// published.
func (c SuperChecks) RingIdentifiers() []string {
	return surfaceRingIdentifiers("super")
}

// Run reads the current boot, then judges its freshness, the trace's
// consistency with what was read last cycle, the boot that ended when the
// current one replaced the one read last cycle, and the three surfaces
// against their owners' accounts. A boot with no start line has no
// reference for tick-fresh, which fails as it does on an unreadable
// trace.
func (c SuperChecks) Run(cfg *Config, st *State, peers map[string]PeerView) []Finding {
	boot, _, err := traceReadCurrent(st, cfg.TracesRoot)
	readable := err == nil && len(boot.Records) > 0 && boot.Records[0].Start != nil
	var out []Finding
	switch {
	case err != nil:
		out = append(out, Finding{Check: checkTraceReadable, Subject: gtSubject(err)})
		out = append(out, tickFreshUnread()...)
	case !readable:
		out = append(out, Finding{Check: checkTraceReadable, Subject: gtBootName(boot.Number)})
		out = append(out, tickFreshUnread()...)
	default:
		out = append(out, tickFreshFindings(boot, cfg.Now, c.TunnelMargins.TickMaxAge)...)
	}
	if err != nil {
		out = append(out, traceConsistentUnread()...)
	} else {
		previous := st.TraceBoot
		out = append(out, traceConsistentFindings(st, boot)...)
		out = append(out, bootEndedFindings(st, cfg.TracesRoot, previous, boot, cfg.Now, c.TunnelMargins.TickMaxAge)...)
	}
	out = append(out, surfaceDisagreements("super", boot, readable, cfg.Now, c.TunnelMargins, substanceJudgeFor(cfg, st), peers)...)
	return out
}
