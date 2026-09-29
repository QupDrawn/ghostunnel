package main

// surface_tunnel.go is the tunnel surface as the proxy's own trace records
// it (observers/README, "About ghostunnel"): the checks over the mTLS data
// path that need nothing but the current boot. The tunnel member runs them
// as its own (tunnelchecks.go); every other member runs them too, from its
// own byte-identical copy of this file, and compares what it computes with
// what the tunnel member published (surfaces.go, SPEC 14.3). The listener
// expectation is not here: it is the tunnel member's own configuration.
//
// The clock is the reader's own wall clock for the cycle. The trace and the
// reader are on the same host, so the comparison of an accept's `at`
// against now is exact to the whole second the trace records.

import (
	"sort"
	"strconv"
	"time"
	"unicode/utf8"
)

// The tunnel surface's check identifiers (SPEC 15: constants of the
// members' own code, spelled the same in every copy).
const (
	// checkConnConsistent: every handshake, acl and close names a
	// connection an earlier accept opened, and no connection has two
	// accepts, handshakes, acls or closes. Subject: the connection id.
	checkConnConsistent = "conn-consistent"
	// checkHandshakeVerified: an accepted full handshake completed
	// client-certificate verification. Subject: the connection id.
	checkHandshakeVerified = "handshake-verified"
	// checkResumptionVerified: an accepted resumed session completed
	// verification on this handshake rather than carrying it over. The
	// start line's verify_on_resume is what the process promises; the
	// handshake's verified is what happened, and only the latter is
	// judged here. Subject: the connection id.
	checkResumptionVerified = "resumption-verified"
	// checkACLBeforeServe: a connection whose handshake was accepted was
	// allowed by the access-control list before it served: one that was
	// denied, or never decided, is closed as refused and nothing else, and
	// a decision that is still missing after the grace is a missing
	// decision. Subject: the connection id.
	checkACLBeforeServe = "acl-before-serve"
	// checkLifetimeCap: no connection outlives lifetime_cap_seconds plus
	// the margin, closed or still open. Subject: the connection id.
	checkLifetimeCap = "lifetime-cap"
	// checkAcceptLoop: no Accept on the tunnel listener failed within the
	// last tick max-age (an accept-error line that recent). Subject: the
	// error text, cut to 64 bytes.
	checkAcceptLoop = "accept-loop"
)

// Defaults for the margins when the zero value is used. Every member that
// judges this surface must judge with the values the tunnel member runs
// with, or the two disagree.
const (
	defaultLifetimeMargin = 2 * time.Second
	defaultACLGrace       = 2 * time.Second
)

// tunnelSurfaceIdentifiers lists the surface's checks in evaluation order:
// the rules of this file, then the two substance rules of substance.go,
// which re-judge from the chains on disk what the lines here take the
// proxy's word for.
var tunnelSurfaceIdentifiers = []string{checkConnConsistent, checkHandshakeVerified, checkResumptionVerified, checkACLBeforeServe, checkLifetimeCap, checkAcceptLoop, checkHandshakeSubstance, checkACLSubstance}

// acceptLoopSubjectBytes bounds accept-loop's subject, the error text.
const acceptLoopSubjectBytes = 64

// boundBytes returns s cut to at most n bytes, never inside a rune, so a
// subject stays valid UTF-8 whatever the trace carried.
func boundBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// resolveTunnelMargins is m with the default in place of every zero.
func resolveTunnelMargins(m surfaceMargins) surfaceMargins {
	if m.LifetimeMargin == 0 {
		m.LifetimeMargin = defaultLifetimeMargin
	}
	if m.ACLGrace == 0 {
		m.ACLGrace = defaultACLGrace
	}
	if m.TickMaxAge <= 0 {
		m.TickMaxAge = defaultTickMaxAge
	}
	return m
}

// tunnelConn is one connection's lines in the current boot: for each kind,
// the index in the boot's records, plus one, of the connection's first
// line of that kind; 0 for none.
type tunnelConn struct {
	accept    int
	handshake int
	acl       int
	close     int
}

// tunnelState is what the rules of this file hold of the records judged so
// far: every connection's lines, the connections that do not add up, the
// connections a rule may still find against, and the accept-error lines.
// Everything in it is a fact of the records, never a verdict that rests on
// the clock; the findings are computed from it against now every time
// (findings). The whole boot is judged by adding every record in order to
// a new state (tunnelSurfaceFindings); the kept judgement (judgememory.go)
// adds each cycle only the records it has not judged.
type tunnelState struct {
	// capped is a lifetime cap in force, and capMS the cap with its margin
	// in milliseconds, by which a closed connection is lasting: the start
	// line and the margin are the state's for its whole life.
	capped       bool
	capMS        int64
	conns        map[int64]*tunnelConn
	inconsistent map[int64]bool
	// served are the connections that handshake-verified, resumption-
	// verified or acl-before-serve may find against, now or once the grace
	// has passed: every accepted handshake but a verified one that was
	// allowed, or closed as refused. A connection not here yields none of
	// the three whatever the clock says, until a line of it moves it here.
	served map[int64]bool
	// lasting are the connections lifetime-cap may find against: closed
	// after more than the cap, or accepted and still open.
	lasting map[int64]bool
	// acceptErrors are the accept-error lines as indices in the records,
	// in record order; ordered holds while their times never go back, as
	// the reader's rule 10 holds every line to.
	acceptErrors []int
	ordered      bool
}

// newTunnelState is the state of no record judged, under the boot's start
// line and the lifetime margin.
func newTunnelState(start *gtStart, lifetimeMargin time.Duration) *tunnelState {
	return &tunnelState{
		capped:       start.Config.LifetimeCapSeconds > 0,
		capMS:        start.Config.LifetimeCapSeconds*1000 + lifetimeMargin.Milliseconds(),
		conns:        map[int64]*tunnelConn{},
		inconsistent: map[int64]bool{},
		served:       map[int64]bool{},
		lasting:      map[int64]bool{},
		ordered:      true,
	}
}

// tunnelSurfaceFindings judges a readable current boot with a start line,
// every record of it. lifetimeMargin is the margin over the lifetime cap
// (ringtrace/README 1.2: the trace records whole seconds and a close lands
// after the cap fires); aclGrace is how long after an accepted handshake
// its acl line, and after a denial its refused close, may still be missing
// before the absence is a finding; tickMaxAge is how far back accept-loop
// looks for a failed Accept (the same value tick-fresh allows the newest
// tick, tracememory.go). Zero means the default for any of them.
func tunnelSurfaceFindings(boot *gtBoot, now time.Time, lifetimeMargin, aclGrace, tickMaxAge time.Duration) []Finding {
	m := resolveTunnelMargins(surfaceMargins{LifetimeMargin: lifetimeMargin, ACLGrace: aclGrace, TickMaxAge: tickMaxAge})
	s := newTunnelState(boot.Records[0].Start, m.LifetimeMargin)
	for i := range boot.Records {
		s.add(boot.Records, i)
	}
	return s.findings(boot.Records, now, m)
}

// add judges record i of recs into the state. The connection a line names
// gathers it; anything that does not add up is conn-consistent: a line of
// a connection no earlier accept opened, or a second line of one kind,
// which changes nothing else.
func (s *tunnelState) add(recs []gtRecord, i int) {
	rec := &recs[i]
	var id int64
	switch rec.Kind {
	case "accept":
		id = rec.Accept.Conn
		if s.conns[id] != nil {
			s.inconsistent[id] = true
			return
		}
		cn := &tunnelConn{accept: i + 1}
		s.conns[id] = cn
		s.classify(recs, id, cn)
		return
	case "handshake":
		id = rec.Handshake.Conn
	case "acl":
		id = rec.ACL.Conn
	case "close":
		id = rec.Close.Conn
	case "accept-error":
		if n := len(s.acceptErrors); n > 0 && rec.At.Before(recs[s.acceptErrors[n-1]].At) {
			s.ordered = false
		}
		s.acceptErrors = append(s.acceptErrors, i)
		return
	default:
		return
	}
	cn := s.conns[id]
	if cn == nil {
		s.inconsistent[id] = true
		cn = &tunnelConn{}
		s.conns[id] = cn
	}
	field := &cn.close
	switch rec.Kind {
	case "handshake":
		field = &cn.handshake
	case "acl":
		field = &cn.acl
	}
	if *field != 0 {
		s.inconsistent[id] = true
		return
	}
	*field = i + 1
	s.classify(recs, id, cn)
}

// classify puts a connection whose lines changed into served and lasting,
// or takes it out.
func (s *tunnelState) classify(recs []gtRecord, id int64, cn *tunnelConn) {
	served := false
	if cn.handshake != 0 {
		hs := recs[cn.handshake-1].Handshake
		allowed := cn.acl != 0 && recs[cn.acl-1].ACL.Decision == "allow"
		refused := cn.close != 0 && recs[cn.close-1].Close.Reason == "refused"
		served = hs.Outcome == "ok" && (!hs.Verified || !allowed && !refused)
	}
	if served {
		s.served[id] = true
	} else {
		delete(s.served, id)
	}
	if s.capped && (cn.accept != 0 && cn.close == 0 || cn.close != 0 && recs[cn.close-1].Close.DurationMS > s.capMS) {
		s.lasting[id] = true
	} else {
		delete(s.lasting, id)
	}
}

// sortedConns is the set's connection ids in increasing order.
func sortedConns(set map[int64]bool) []int64 {
	out := make([]int64, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// findings is the rules' findings over the records the state has judged,
// which are recs, every one, against now: conn-consistent, then
// verification and the access-control list per accepted handshake, then
// the lifetime cap, each in connection id order, then the accept loop. m
// is resolved (resolveTunnelMargins).
func (s *tunnelState) findings(recs []gtRecord, now time.Time, m surfaceMargins) []Finding {
	var out []Finding
	fail := func(check string, subject string) {
		out = append(out, Finding{Check: check, Subject: subject})
	}
	line := func(i int) *gtRecord {
		if i == 0 {
			return nil
		}
		return &recs[i-1]
	}

	for _, id := range sortedConns(s.inconsistent) {
		fail(checkConnConsistent, strconv.FormatInt(id, 10))
	}

	// Verification and the access-control list, per accepted handshake.
	for _, id := range sortedConns(s.served) {
		cn := s.conns[id]
		subject := strconv.FormatInt(id, 10)
		hs, acl, cl := line(cn.handshake), line(cn.acl), line(cn.close)
		if hs == nil || hs.Handshake.Outcome != "ok" {
			continue
		}
		if !hs.Handshake.Verified {
			if hs.Handshake.Resumed {
				fail(checkResumptionVerified, subject)
			} else {
				fail(checkHandshakeVerified, subject)
			}
		}
		switch {
		case acl != nil && acl.ACL.Decision == "allow":
			// Allowed before serving.
		case cl != nil:
			// Denied or undecided: the only close is a refusal.
			if cl.Close.Reason != "refused" {
				fail(checkACLBeforeServe, subject)
			}
		default:
			// Denied or undecided and still open: the refusal, or the
			// decision, is overdue once the grace has passed.
			since := hs.At
			if acl != nil && acl.At.After(since) {
				since = acl.At
			}
			if now.Sub(since) > m.ACLGrace {
				fail(checkACLBeforeServe, subject)
			}
		}
	}

	// The lifetime cap, closed and open.
	if cap := recs[0].Start.Config.LifetimeCapSeconds; cap > 0 {
		capMS := cap*1000 + m.LifetimeMargin.Milliseconds()
		for _, id := range sortedConns(s.lasting) {
			cn := s.conns[id]
			subject := strconv.FormatInt(id, 10)
			accept, cl := line(cn.accept), line(cn.close)
			switch {
			case cl != nil:
				if cl.Close.DurationMS > capMS {
					fail(checkLifetimeCap, subject)
				}
			case accept != nil:
				if now.Sub(accept.At) > time.Duration(cap)*time.Second+m.LifetimeMargin {
					fail(checkLifetimeCap, subject)
				}
			}
		}
	}

	// The accept loop: an Accept that failed within the window is a
	// listener that is not accepting (out of file descriptors, say), which
	// before the accept-error line backed off silently. One finding per
	// distinct error text; the subject is that text, bounded. While the
	// lines' times never go back, those older than the window are a
	// leading run, passed over by a search; every line after it is still
	// held to the window.
	errs := s.acceptErrors
	if s.ordered {
		errs = errs[sort.Search(len(errs), func(k int) bool { return now.Sub(recs[errs[k]].At) <= m.TickMaxAge }):]
	}
	seenErr := map[string]bool{}
	for _, i := range errs {
		rec := &recs[i]
		if now.Sub(rec.At) > m.TickMaxAge {
			continue
		}
		subject := boundBytes(rec.AcceptError.Error, acceptLoopSubjectBytes)
		if !seenErr[subject] {
			seenErr[subject] = true
			fail(checkAcceptLoop, subject)
		}
	}
	return out
}
