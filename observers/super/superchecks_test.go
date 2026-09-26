package main

// superchecks_test.go proves the super member's local checks: the trace
// is read and its unreadability reported, the three surfaces are judged
// against their owners' accounts, and the trace's consistency across
// cycles is kept. The rules themselves are proved in surfaces_test.go and
// tracememory_test.go, of which this member carries its own copies.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func superRun(t *testing.T, root string, st *State, peers map[string]PeerView) []Finding {
	t.Helper()
	now, err := time.Parse(time.RFC3339, "2026-09-24T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	checks := SuperChecks{}
	got := checks.Run(&Config{TracesRoot: root, Now: now}, st, peers)
	sort.Slice(got, func(i, j int) bool {
		if got[i].Check != got[j].Check {
			return got[i].Check < got[j].Check
		}
		return got[i].Subject < got[j].Subject
	})
	ids := map[string]bool{}
	for _, id := range checks.Identifiers() {
		ids[id] = true
	}
	for _, id := range checks.RingIdentifiers() {
		ids[strings.SplitN(id, ":", 2)[0]] = true
	}
	for _, f := range got {
		if !ids[f.Check] {
			t.Fatalf("finding %v names an undeclared identifier", f)
		}
	}
	return got
}

func superWant(t *testing.T, got []Finding, want ...Finding) {
	t.Helper()
	sort.Slice(want, func(i, j int) bool {
		if want[i].Check != want[j].Check {
			return want[i].Check < want[j].Check
		}
		return want[i].Subject < want[j].Subject
	})
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("findings\n got %v\nwant %v", got, want)
	}
}

func superPeers() map[string]PeerView {
	out := map[string]PeerView{}
	for _, o := range []string{"tunnel", "admin", "material"} {
		out[o] = PeerView{Verdict: VerdictAlive, Checks: surfaceIdentifiers(o)}
	}
	return out
}

// superLines is the healthy boot of gtLines with a tick one second before
// superRun's now, so that tick-fresh holds. gtLines's own indices are
// unchanged.
func superLines() []string {
	return append(append([]string{}, gtLines...), `{"kind":"tick","version":1,"sequence":10,"at":"2026-09-24T11:59:59Z"}`)
}

func TestSuperIdentifiers(t *testing.T) {
	if got := (SuperChecks{}).Identifiers(); fmt.Sprint(got) != fmt.Sprint([]string{"trace-readable", "tick-fresh", "trace-consistent", "boot-ended"}) {
		t.Fatalf("identifiers %v", got)
	}
	if got := (SuperChecks{}).RingIdentifiers(); fmt.Sprint(got) != fmt.Sprint([]string{"surface-disagree:admin", "surface-disagree:material", "surface-disagree:tunnel"}) {
		t.Fatalf("ring identifiers %v", got)
	}
}

func TestSuperJudgesTheRing(t *testing.T) {
	root := gtOneBoot(t, superLines()...)
	superWant(t, superRun(t, root, &State{}, superPeers()))
	// The tunnel member stopped listing lifetime-cap and accept-loop.
	peers := superPeers()
	peers["tunnel"] = PeerView{Verdict: VerdictAlive, Checks: []string{"conn-consistent", "handshake-verified", "resumption-verified", "acl-before-serve", "handshake-substance", "acl-substance"}}
	superWant(t, superRun(t, root, &State{}, peers), Finding{"surface-disagree", "tunnel:lifetime-cap"}, Finding{"surface-disagree", "tunnel:accept-loop"})
	// The admin surface fails here and the admin member's fault does not
	// say so.
	lines := superLines()
	lines[6] = strings.Replace(lines[6], `"authorized":true`, `"authorized":false`, 1)
	superWant(t, superRun(t, gtOneBoot(t, lines...), &State{}, superPeers()), Finding{"surface-disagree", "admin:shutdown-authorized"})
	// The current boot rewritten under this member between two cycles.
	root = gtOneBoot(t, superLines()...)
	st := &State{}
	superWant(t, superRun(t, root, st, superPeers()))
	lines = superLines()
	lines[3] = strings.Replace(lines[3], `"cn matched"`, `"cn matchez"`, 1)
	gtWriteSegment(t, root, "0000000001", "0000000001.trace", gtJoin(lines...))
	superWant(t, superRun(t, root, st, superPeers()), Finding{"trace-consistent", "0000000001/0000000001.trace"})
}

func TestSuperTickFresh(t *testing.T) {
	// gtLines alone: the newest tick is at 11:02:05, an hour before now.
	superWant(t, superRun(t, gtOneBoot(t, gtLines...), &State{}, superPeers()), Finding{"tick-fresh", "2026-09-24T11:02:05Z"})
	// No tick at all: the start line is the reference.
	superWant(t, superRun(t, gtOneBoot(t, gtLines[:7]...), &State{}, superPeers()), Finding{"tick-fresh", "2026-09-24T11:00:00Z"})
	// The member's own -tick-max-age forgives it. The same value is
	// accept-loop's window, so gtLines's accept-error at 11:02:06 is left
	// out here, or the tunnel surface would disagree instead.
	now, _ := time.Parse(time.RFC3339, "2026-09-24T12:00:00Z")
	got := SuperChecks{TunnelMargins: surfaceMargins{TickMaxAge: 2 * time.Hour}}.Run(&Config{TracesRoot: gtOneBoot(t, gtLines[:8]...), Now: now}, &State{}, superPeers())
	superWant(t, got)
	// With the accept-error in, that is what a two-hour window computes.
	got = SuperChecks{TunnelMargins: surfaceMargins{TickMaxAge: 2 * time.Hour}}.Run(&Config{TracesRoot: gtOneBoot(t, gtLines...), Now: now}, &State{}, superPeers())
	superWant(t, got, Finding{"surface-disagree", "tunnel:accept-loop"})
}

func TestSuperUnreadableTrace(t *testing.T) {
	var all []Finding
	for _, o := range []string{"tunnel", "admin", "material"} {
		for _, id := range surfaceIdentifiers(o) {
			all = append(all, Finding{"surface-disagree", o + ":" + id})
		}
	}
	unread := append([]Finding{{"trace-readable", "gt"}, {"tick-fresh", ""}, {"trace-consistent", ""}}, all...)
	superWant(t, superRun(t, "", &State{}, superPeers()), unread...)
	superWant(t, superRun(t, filepath.Join(t.TempDir(), "gt"), &State{}, superPeers()), unread...)
	// A current boot with no start line yet: readable, not judgeable, and
	// with no reference for tick-fresh.
	root := gtOneBoot(t, superLines()...)
	if err := os.Mkdir(filepath.Join(root, "0000000002"), 0o755); err != nil {
		t.Fatal(err)
	}
	superWant(t, superRun(t, root, &State{}, superPeers()), append([]Finding{{"trace-readable", "0000000002"}, {"tick-fresh", ""}}, all...)...)
	// Owners that could not read it either publish every check failing:
	// agreed, and only this member's own reading is left.
	peers := superPeers()
	for o, pv := range peers {
		pv.Verdict = VerdictFaulted
		pv.FaultPresent, pv.FaultParsed = true, true
		for _, id := range surfaceIdentifiers(o) {
			pv.Failing = append(pv.Failing, Finding{Check: id})
		}
		peers[o] = pv
	}
	superWant(t, superRun(t, "", &State{}, peers), Finding{"trace-readable", "gt"}, Finding{"tick-fresh", ""}, Finding{"trace-consistent", ""})
}
