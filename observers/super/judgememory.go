package main

// judgememory.go is the judgement of the tunnel surface kept across cycles
// (SPEC 14.3): the rules of surface_tunnel.go and the two substance rules
// of substance.go hold, of the records they have judged, the facts every
// later verdict needs (each connection's lines, the material in force, the
// substance verdicts that may be kept), and a cycle extends that from the
// records not yet judged instead of judging the whole boot again. It exists
// so that a member's cycle does not grow with the length of the boot; what
// it computes is, finding for finding and in order, what judging every
// record of the boot computes.
//
// It is kept only while it is proven that the records it judged are the
// records now. The judgement covers records [0:judged) of one read of one
// boot; the next cycle's read reuses it only if that read is the very next
// read made with the same decode memory (gtBoot.Memory, gtBoot.Read), took
// at least those judged leading records unchanged from that memory
// (gtBoot.Carried: decoded from bytes that hash the same now, from the
// same reader state), is of the same boot (the root, the boot number, and
// the SHA-256 of the start line's bytes), and is judged under the same
// margins, query and material base. Anything else, a prefix rewritten, a
// read not judged in between, a new boot, is judged from no record at all:
// the memory fails closed to the full judgement.
//
// Nothing that reads the clock is kept. The grace of acl-before-serve, the
// lifetime cap of an open connection and the window of accept-loop are
// computed against now every cycle from the facts kept; tick-fresh is not
// here and reads the boot every cycle. Chains, CA bundles and policy files
// are read and hashed every cycle, and a kept substance verdict answers
// only while every file it rests on reads clean (substanceState).
//
// The memory is in process, like the decode memory, never persisted, and
// replaced whole when the boot changes. Every member carries a
// byte-identical copy of this file.

import (
	"bytes"
	"time"
)

// tunnelJudgement is the kept judgement. Its zero value holds nothing.
type tunnelJudgement struct {
	// The read and the boot the judgement is of.
	decode *gtDecodeMemory
	read   uint64
	root   string
	number int64
	start  string
	// The values it was judged under.
	margins      surfaceMargins
	materialBase string
	policyQuery  string
	// judged is how many leading records of the boot are judged.
	judged    int
	tunnel    *tunnelState
	substance *substanceState
}

// tunnelFindings judges a readable current boot with a start line by the
// tunnel surface's rules, surface_tunnel.go's and then the two substance
// rules, extending the judgement kept in j (j.Kept; nil judges every
// record) from the records it has not judged.
func tunnelFindings(boot *gtBoot, now time.Time, m surfaceMargins, j substanceJudge) []Finding {
	m = resolveTunnelMargins(m)
	k := j.Kept
	if k == nil {
		k = &tunnelJudgement{}
	}
	k.resume(boot, m, j)
	recs := boot.Records
	for i := k.judged; i < len(recs); i++ {
		k.tunnel.add(recs, i)
		k.substance.add(recs, i)
	}
	k.judged = len(recs)
	out := k.tunnel.findings(recs, now, m)
	return append(out, k.substance.findings(newSubstanceCycle(boot, j), recs)...)
}

// resume keeps the judgement for this read when it is proven to cover
// records the read holds unchanged, and otherwise starts it again from no
// record. Either way it is then the judgement of this read.
func (k *tunnelJudgement) resume(boot *gtBoot, m surfaceMargins, j substanceJudge) {
	start := gtStartLineHash(boot)
	keep := k.tunnel != nil &&
		boot.Memory != nil && boot.Memory == k.decode && boot.Read == k.read+1 &&
		k.judged <= boot.Carried &&
		start != "" && start == k.start && boot.Root == k.root && boot.Number == k.number &&
		m == k.margins && j.MaterialBase == k.materialBase && j.PolicyQuery == k.policyQuery
	if !keep {
		first := boot.Records[0].Start
		*k = tunnelJudgement{
			root: boot.Root, number: boot.Number, start: start,
			margins: m, materialBase: j.MaterialBase, policyQuery: j.PolicyQuery,
			tunnel:    newTunnelState(first, m.LifetimeMargin),
			substance: newSubstanceState(first),
		}
	}
	k.decode, k.read = boot.Memory, boot.Read
}

// gtStartLineHash is the SHA-256 of the bytes of the boot's first line,
// its start line, as read: the first segment's prefix up to and including
// its first line feed. "" when the read holds no such line.
func gtStartLineHash(boot *gtBoot) string {
	if len(boot.Segments) == 0 {
		return ""
	}
	p := boot.Segments[0].Prefix
	end := bytes.IndexByte(p, '\n')
	if end < 0 {
		return ""
	}
	return hashPrefix(p[:end+1])
}
