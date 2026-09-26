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

// tunnelConn is one connection's lines in the current boot.
type tunnelConn struct {
	accept    *gtRecord
	handshake *gtRecord
	acl       *gtRecord
	close     *gtRecord
}

// tunnelSurfaceFindings judges a readable current boot with a start line.
// lifetimeMargin is the margin over the lifetime cap (ringtrace/README
// 1.2: the trace records whole seconds and a close lands after the cap
// fires); aclGrace is how long after an accepted handshake its acl line,
// and after a denial its refused close, may still be missing before the
// absence is a finding; tickMaxAge is how far back accept-loop looks for
// a failed Accept (the same value tick-fresh allows the newest tick,
// tracememory.go). Zero means the default for any of them.
func tunnelSurfaceFindings(boot *gtBoot, now time.Time, lifetimeMargin, aclGrace, tickMaxAge time.Duration) []Finding {
	if lifetimeMargin == 0 {
		lifetimeMargin = defaultLifetimeMargin
	}
	if aclGrace == 0 {
		aclGrace = defaultACLGrace
	}
	if tickMaxAge <= 0 {
		tickMaxAge = defaultTickMaxAge
	}
	start := boot.Records[0].Start
	var out []Finding
	fail := func(check string, subject string) {
		out = append(out, Finding{Check: check, Subject: subject})
	}

	// Gather each connection's lines; anything that does not add up is
	// conn-consistent.
	conns := map[int64]*tunnelConn{}
	var order []int64
	inconsistent := map[int64]bool{}
	get := func(id int64) *tunnelConn {
		cn := conns[id]
		if cn == nil {
			inconsistent[id] = true
			cn = &tunnelConn{}
			conns[id] = cn
			order = append(order, id)
		}
		return cn
	}
	for i := range boot.Records {
		rec := &boot.Records[i]
		switch rec.Kind {
		case "accept":
			if conns[rec.Accept.Conn] != nil {
				inconsistent[rec.Accept.Conn] = true
				continue
			}
			conns[rec.Accept.Conn] = &tunnelConn{accept: rec}
			order = append(order, rec.Accept.Conn)
		case "handshake":
			cn := get(rec.Handshake.Conn)
			if cn.handshake != nil {
				inconsistent[rec.Handshake.Conn] = true
				continue
			}
			cn.handshake = rec
		case "acl":
			cn := get(rec.ACL.Conn)
			if cn.acl != nil {
				inconsistent[rec.ACL.Conn] = true
				continue
			}
			cn.acl = rec
		case "close":
			cn := get(rec.Close.Conn)
			if cn.close != nil {
				inconsistent[rec.Close.Conn] = true
				continue
			}
			cn.close = rec
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, id := range order {
		if inconsistent[id] {
			fail(checkConnConsistent, strconv.FormatInt(id, 10))
		}
	}

	// Verification and the access-control list, per accepted handshake.
	for _, id := range order {
		cn := conns[id]
		subject := strconv.FormatInt(id, 10)
		hs := cn.handshake
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
		case cn.acl != nil && cn.acl.ACL.Decision == "allow":
			// Allowed before serving.
		case cn.close != nil:
			// Denied or undecided: the only close is a refusal.
			if cn.close.Close.Reason != "refused" {
				fail(checkACLBeforeServe, subject)
			}
		default:
			// Denied or undecided and still open: the refusal, or the
			// decision, is overdue once the grace has passed.
			since := hs.At
			if cn.acl != nil && cn.acl.At.After(since) {
				since = cn.acl.At
			}
			if now.Sub(since) > aclGrace {
				fail(checkACLBeforeServe, subject)
			}
		}
	}

	// The lifetime cap, closed and open.
	if cap := start.Config.LifetimeCapSeconds; cap > 0 {
		capMS := cap*1000 + lifetimeMargin.Milliseconds()
		for _, id := range order {
			cn := conns[id]
			subject := strconv.FormatInt(id, 10)
			switch {
			case cn.close != nil:
				if cn.close.Close.DurationMS > capMS {
					fail(checkLifetimeCap, subject)
				}
			case cn.accept != nil:
				if now.Sub(cn.accept.At) > time.Duration(cap)*time.Second+lifetimeMargin {
					fail(checkLifetimeCap, subject)
				}
			}
		}
	}

	// The accept loop: an Accept that failed within the window is a
	// listener that is not accepting (out of file descriptors, say), which
	// before the accept-error line backed off silently. One finding per
	// distinct error text; the subject is that text, bounded.
	seenErr := map[string]bool{}
	for i := range boot.Records {
		rec := &boot.Records[i]
		if rec.Kind != "accept-error" || now.Sub(rec.At) > tickMaxAge {
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
