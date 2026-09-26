package main

// surfaces.go is surface-disagree (SPEC 14.3): every member judges the
// proxy's trace for every surface, from its own copy of each surface's
// rules (surface_tunnel.go, surface_admin.go, surface_material.go), and
// compares what it computes with what the surface's owner published. A
// surface has a single judge only if nobody else looks; when everybody
// looks, an owner that stops reporting what its own rules find, or stops
// running them, is seen by the other three. The file and process checks
// (material-loaded, key-private, sandbox-applied, cmdline-carries-no-secret,
// proxy-process-alive) stay with their owner: they read the owner's host,
// which the others cannot; so do the tunnel member's expectations
// (listener-expected, target-expected, acl-expected,
// proxy-protocol-expected), which are its own configuration.
//
// The comparison is at the identifier: an identifier this member computes
// as failing must be in the owner's published fault's failing set, and
// every identifier of the surface must be in the owner's newest
// heartbeat's checks. The subjects are not compared: a connection id or a
// grace crossed between two clocks is the owner's to spell. A member whose
// account is not current (stale or retired, or no heartbeat parsed) is not
// judged; member-fresh or member-present already halts on it.
//
// The order the cycle fixes makes the comparison one-sided: what a member
// published is read at step 4, the trace at step 7, so a condition the
// owner saw clear is one this member sees cleared too. The other direction
// is not so guarded: a condition that begins between the owner's cycle and
// this member's is computed here before the owner publishes it, and the
// halt this raises is the halt the owner raises a cycle later.
//
// Every member carries a byte-identical copy of this file.

import (
	"sort"
	"time"
)

// checkSurfaceDisagree is the identifier (SPEC 15). Subject:
// <owner>:<identifier>. It is about another member: listed in the
// heartbeat's checks once per owner as surface-disagree:<owner>, never in
// the fault.
const checkSurfaceDisagree = "surface-disagree"

// The members that own a surface, by the identity the deployment gives
// them (observers/README). The surfaces are ghostunnel's; the identities
// are the ring's defaults and the deployment's.
const (
	surfaceTunnel   = "tunnel"
	surfaceAdmin    = "admin"
	surfaceMaterial = "material"
)

// surfaceMargins are the tunnel surface's values to be set, which every
// judge of that surface must share with the tunnel member.
type surfaceMargins struct {
	LifetimeMargin time.Duration
	ACLGrace       time.Duration
	// TickMaxAge is the window accept-loop looks back over, and the age
	// tick-fresh allows the newest tick; every member's -tick-max-age.
	TickMaxAge time.Duration
}

// surfaceIdentifiers lists a surface's trace-only checks, nil for a member
// that owns none.
func surfaceIdentifiers(owner string) []string {
	switch owner {
	case surfaceTunnel:
		return tunnelSurfaceIdentifiers
	case surfaceAdmin:
		return adminSurfaceIdentifiers
	case surfaceMaterial:
		return materialSurfaceIdentifiers
	}
	return nil
}

// surfaceFindings judges a readable current boot with a start line by a
// surface's rules. sub is what the tunnel surface's substance rules need
// beyond the boot (substance.go).
func surfaceFindings(owner string, boot *gtBoot, now time.Time, m surfaceMargins, sub substanceJudge) []Finding {
	switch owner {
	case surfaceTunnel:
		out := tunnelSurfaceFindings(boot, now, m.LifetimeMargin, m.ACLGrace, m.TickMaxAge)
		return append(out, substanceFindings(boot, sub)...)
	case surfaceAdmin:
		return adminSurfaceFindings(boot)
	case surfaceMaterial:
		return materialSurfaceFindings(boot)
	}
	return nil
}

// peerSurfaces lists the surfaces self judges for their owners: every
// surface but its own, in identity order.
func peerSurfaces(self string) []string {
	var out []string
	for _, o := range []string{surfaceTunnel, surfaceAdmin, surfaceMaterial} {
		if o != self {
			out = append(out, o)
		}
	}
	sort.Strings(out)
	return out
}

// surfaceRingIdentifiers is what a member lists in its checks for this
// file's work: surface-disagree once per surface it judges (SPEC 15).
func surfaceRingIdentifiers(self string) []string {
	var out []string
	for _, o := range peerSurfaces(self) {
		out = append(out, checkSurfaceDisagree+":"+o)
	}
	return out
}

// surfaceDisagreements is the comparison for every surface self does not
// own. boot is the current boot when readable is true: read under every
// rule and holding a start line. When it is not, every check of every
// surface is computed as failing, because none could run, and the owner
// must have published the same.
func surfaceDisagreements(self string, boot *gtBoot, readable bool, now time.Time, m surfaceMargins, sub substanceJudge, peers map[string]PeerView) []Finding {
	var out []Finding
	for _, owner := range peerSurfaces(self) {
		pv, declared := peers[owner]
		if !declared {
			// Not a member of this ring: nothing published to compare.
			continue
		}
		if pv.Checks == nil || pv.Verdict == VerdictStale || pv.Verdict == VerdictRetired {
			continue
		}
		ids := surfaceIdentifiers(owner)
		computed := map[string]bool{}
		if readable {
			for _, f := range surfaceFindings(owner, boot, now, m, sub) {
				computed[f.Check] = true
			}
		} else {
			for _, id := range ids {
				computed[id] = true
			}
		}
		listed := map[string]bool{}
		for _, id := range pv.Checks {
			listed[id] = true
		}
		published := map[string]bool{}
		if pv.FaultParsed {
			for _, f := range pv.Failing {
				published[f.Check] = true
			}
		}
		for _, id := range ids {
			switch {
			case !listed[id]:
				out = append(out, Finding{Check: checkSurfaceDisagree, Subject: owner + ":" + id})
			case computed[id] && !published[id]:
				// Computed failing here and not in the owner's fault: the
				// owner does not report it, or its fault is present and
				// could not be read, which says nothing either way.
				out = append(out, Finding{Check: checkSurfaceDisagree, Subject: owner + ":" + id})
			}
		}
	}
	return out
}
