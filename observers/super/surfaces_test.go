package main

// surfaces_test.go proves surface-disagree (surfaces.go) for every member
// as self: what a member computes over the proxy's trace for a surface it
// does not own is compared at the identifier with what the owner published,
// one-sidedly, and an owner that stops listing a check is seen. Every
// member carries a byte-identical copy of this file.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

const surfacesNow = "2026-09-24T12:00:00Z"

func sNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, surfacesNow)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

// sBoot reads one boot of lines as the checks would.
func sBoot(t *testing.T, lines ...string) *gtBoot {
	t.Helper()
	b, err := gtReadLatest(gtOneBoot(t, lines...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sPeers is the three owners as current, listing every identifier of their
// surface and carrying no fault.
func sPeers() map[string]PeerView {
	out := map[string]PeerView{}
	for _, o := range []string{surfaceTunnel, surfaceAdmin, surfaceMaterial} {
		out[o] = PeerView{Verdict: VerdictAlive, Checks: append([]string{"halts-readable"}, surfaceIdentifiers(o)...)}
	}
	return out
}

func sSorted(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Check+"("+f.Subject+")")
	}
	sort.Strings(out)
	return out
}

func sWant(t *testing.T, got []Finding, want ...string) {
	t.Helper()
	sort.Strings(want)
	if fmt.Sprint(sSorted(got)) != fmt.Sprint(want) {
		t.Fatalf("findings\n got %v\nwant %v", sSorted(got), want)
	}
}

var selves = []string{surfaceTunnel, surfaceAdmin, surfaceMaterial, "super"}

func TestSurfaceRingIdentifiers(t *testing.T) {
	want := map[string][]string{
		"tunnel":   {"surface-disagree:admin", "surface-disagree:material"},
		"admin":    {"surface-disagree:material", "surface-disagree:tunnel"},
		"material": {"surface-disagree:admin", "surface-disagree:tunnel"},
		"super":    {"surface-disagree:admin", "surface-disagree:material", "surface-disagree:tunnel"},
	}
	for self, w := range want {
		if got := surfaceRingIdentifiers(self); fmt.Sprint(got) != fmt.Sprint(w) {
			t.Errorf("%s: ring identifiers %v, want %v", self, got, w)
		}
	}
	// Every surface identifier is spelled once, and the file and process
	// checks are nobody's surface.
	all := map[string]bool{}
	for _, o := range []string{surfaceTunnel, surfaceAdmin, surfaceMaterial} {
		for _, id := range surfaceIdentifiers(o) {
			if all[id] {
				t.Errorf("identifier %s in two surfaces", id)
			}
			all[id] = true
		}
	}
	for _, id := range []string{"trace-readable", "listener-expected", "target-expected", "acl-expected", "proxy-protocol-expected", "cmdline-carries-no-secret", "proxy-process-alive", "material-loaded", "key-private", "sandbox-applied", "tick-fresh", "trace-consistent", "boot-ambiguous"} {
		if all[id] {
			t.Errorf("%s is a file, process or every-member check and must stay with its owner", id)
		}
	}
	// The accept loop is the tunnel surface's: every member judges it.
	if !all["accept-loop"] {
		t.Errorf("accept-loop is not in a surface")
	}
}

func TestSurfaceAcceptLoopWindowIsShared(t *testing.T) {
	// An accept-error 20 s before now fails accept-loop under the default
	// window of 30 s, and only a window of 10 s forgives it. The judge
	// must use the tunnel member's window, or the two disagree.
	lines := append([]string{}, gtLines[:7]...)
	lines = append(lines, `{"kind":"accept-error","version":1,"sequence":8,"at":"2026-09-24T11:59:40Z","error":"accept tcp 127.0.0.1:8443: too many open files","backoff_ms":5}`)
	boot := sBoot(t, lines...)
	now := sNow(t)
	sWant(t, surfaceDisagreements("super", boot, true, now, surfaceMargins{}, substanceJudge{}, sPeers()), "surface-disagree(tunnel:accept-loop)")
	sWant(t, surfaceDisagreements("super", boot, true, now, surfaceMargins{TickMaxAge: 10 * time.Second}, substanceJudge{}, sPeers()))
	// The tunnel member publishing it: agreed.
	peers := sPeers()
	pv := peers[surfaceTunnel]
	pv.Verdict = VerdictFaulted
	pv.FaultPresent, pv.FaultParsed = true, true
	pv.Failing = []Finding{{Check: "accept-loop", Subject: "accept tcp 127.0.0.1:8443: too many open files"}}
	peers[surfaceTunnel] = pv
	sWant(t, surfaceDisagreements("super", boot, true, now, surfaceMargins{}, substanceJudge{}, peers))
}

func TestSurfaceHealthyBootAgreesWithHealthyOwners(t *testing.T) {
	boot := sBoot(t, gtLines...)
	for _, self := range selves {
		sWant(t, surfaceDisagreements(self, boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, sPeers()))
	}
}

func TestSurfaceOwnerNotListingACheck(t *testing.T) {
	boot := sBoot(t, gtLines...)
	peers := sPeers()
	pv := peers[surfaceAdmin]
	pv.Checks = []string{"status-listener-bound", "pprof-cmdline-redacted", "status-listener-up"} // no shutdown-authorized
	peers[surfaceAdmin] = pv
	for _, self := range selves {
		if self == surfaceAdmin {
			// A member does not judge its own surface.
			sWant(t, surfaceDisagreements(self, boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, peers))
			continue
		}
		sWant(t, surfaceDisagreements(self, boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, peers), "surface-disagree(admin:shutdown-authorized)")
	}
}

func TestSurfaceComputedFailureTheOwnerDidNotPublish(t *testing.T) {
	// An unauthorized shutdown: the admin surface fails
	// shutdown-authorized; the tunnel and material surfaces are healthy.
	lines := append([]string{}, gtLines...)
	lines[6] = strings.Replace(lines[6], `"authorized":true`, `"authorized":false`, 1)
	boot := sBoot(t, lines...)
	now := sNow(t)
	for _, self := range []string{surfaceTunnel, surfaceMaterial, "super"} {
		// No fault at all: not published.
		sWant(t, surfaceDisagreements(self, boot, true, now, surfaceMargins{}, substanceJudge{}, sPeers()), "surface-disagree(admin:shutdown-authorized)")
		// A fault that lists it, whatever the subject: agreed.
		peers := sPeers()
		pv := peers[surfaceAdmin]
		pv.Verdict = VerdictFaulted
		pv.FaultPresent, pv.FaultParsed = true, true
		pv.Failing = []Finding{{Check: "shutdown-authorized", Subject: "something-else"}}
		peers[surfaceAdmin] = pv
		sWant(t, surfaceDisagreements(self, boot, true, now, surfaceMargins{}, substanceJudge{}, peers))
		// A fault that lists other things only: not published.
		pv.Failing = []Finding{{Check: "cmdline-carries-no-secret", Subject: "--storepass"}}
		peers[surfaceAdmin] = pv
		sWant(t, surfaceDisagreements(self, boot, true, now, surfaceMargins{}, substanceJudge{}, peers), "surface-disagree(admin:shutdown-authorized)")
		// A fault present that could not be read says nothing: disagree.
		pv.FaultParsed, pv.Failing = false, nil
		peers[surfaceAdmin] = pv
		sWant(t, surfaceDisagreements(self, boot, true, now, surfaceMargins{}, substanceJudge{}, peers), "surface-disagree(admin:shutdown-authorized)")
	}
	// The admin member itself computes nothing about its own surface here.
	sWant(t, surfaceDisagreements(surfaceAdmin, boot, true, now, surfaceMargins{}, substanceJudge{}, sPeers()))
}

func TestSurfaceOwnerFailingWhatThisMemberDoesNot(t *testing.T) {
	// The comparison is one-sided: an owner that publishes a failure this
	// member does not compute is not a disagreement (its clock, its grace).
	boot := sBoot(t, gtLines...)
	peers := sPeers()
	pv := peers[surfaceTunnel]
	pv.Verdict = VerdictFaulted
	pv.FaultPresent, pv.FaultParsed = true, true
	pv.Failing = []Finding{{Check: "acl-before-serve", Subject: "7"}}
	peers[surfaceTunnel] = pv
	for _, self := range []string{surfaceAdmin, surfaceMaterial, "super"} {
		sWant(t, surfaceDisagreements(self, boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, peers))
	}
}

func TestSurfaceNotCurrentOwnersAreNotJudged(t *testing.T) {
	lines := append([]string{}, gtLines...)
	lines[6] = strings.Replace(lines[6], `"authorized":true`, `"authorized":false`, 1)
	boot := sBoot(t, lines...)
	for _, verdict := range []Verdict{VerdictStale, VerdictRetired} {
		peers := sPeers()
		pv := peers[surfaceAdmin]
		pv.Verdict = verdict
		peers[surfaceAdmin] = pv
		sWant(t, surfaceDisagreements("super", boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, peers))
	}
	// No heartbeat parsed: nothing to compare with.
	peers := sPeers()
	peers[surfaceAdmin] = PeerView{Verdict: VerdictUnknown}
	sWant(t, surfaceDisagreements("super", boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, peers))
	// Not declared at all: nothing to compare with.
	delete(peers, surfaceAdmin)
	sWant(t, surfaceDisagreements("super", boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, peers))
	// Unknown with a heartbeat (the first cycle) is judged.
	peers = sPeers()
	pv := peers[surfaceAdmin]
	pv.Verdict = VerdictUnknown
	peers[surfaceAdmin] = pv
	sWant(t, surfaceDisagreements("super", boot, true, sNow(t), surfaceMargins{}, substanceJudge{}, peers), "surface-disagree(admin:shutdown-authorized)")
}

func TestSurfaceUnreadableTraceComputesEveryCheckFailing(t *testing.T) {
	now := sNow(t)
	// Owners whose faults say nothing: every identifier disagrees.
	var want []string
	for _, o := range []string{surfaceAdmin, surfaceMaterial, surfaceTunnel} {
		for _, id := range surfaceIdentifiers(o) {
			want = append(want, "surface-disagree("+o+":"+id+")")
		}
	}
	sWant(t, surfaceDisagreements("super", nil, false, now, surfaceMargins{}, substanceJudge{}, sPeers()), want...)
	// Owners that could not read it either publish every check failing,
	// as their own allFail does: agreed.
	peers := sPeers()
	for o, pv := range peers {
		pv.Verdict = VerdictFaulted
		pv.FaultPresent, pv.FaultParsed = true, true
		pv.Failing = []Finding{{Check: "trace-readable", Subject: "gt"}}
		for _, id := range surfaceIdentifiers(o) {
			pv.Failing = append(pv.Failing, Finding{Check: id})
		}
		peers[o] = pv
	}
	sWant(t, surfaceDisagreements("super", nil, false, now, surfaceMargins{}, substanceJudge{}, peers))
}

func TestSurfaceMarginsAreShared(t *testing.T) {
	// A connection accepted 103 s ago and still open against a 100 s cap
	// has outlived it by the default margin of 2 s, and only a margin of
	// a minute forgives it. The judge must use the tunnel member's margin,
	// or the two disagree.
	lines := append([]string{}, gtLines[:2]...)
	lines[0] = strings.Replace(lines[0], `"lifetime_cap_seconds":300`, `"lifetime_cap_seconds":100`, 1)
	lines[1] = strings.Replace(lines[1], `"at":"2026-09-24T11:00:01Z"`, `"at":"2026-09-24T11:58:17Z"`, 1)
	boot := sBoot(t, lines...)
	now := sNow(t)
	sWant(t, surfaceDisagreements("super", boot, true, now, surfaceMargins{}, substanceJudge{}, sPeers()), "surface-disagree(tunnel:lifetime-cap)")
	sWant(t, surfaceDisagreements("super", boot, true, now, surfaceMargins{LifetimeMargin: time.Minute}, substanceJudge{}, sPeers()))
}
