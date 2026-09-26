package main

// surface_material.go is the material surface as the proxy's own trace
// records it (observers/README, "About ghostunnel"): the checks over the
// trust material's reload and the session-resumption configuration that
// need nothing but the current boot. The material member runs them as its
// own (materialchecks.go); every other member runs them too, from its own
// byte-identical copy of this file, and compares what it computes with
// what the material member published (surfaces.go, SPEC 14.3). The files
// on disk and the process sandbox are not here: they are read from the
// host, by the material member alone.

// The material surface's check identifiers (SPEC 15: constants of the
// members' own code, spelled the same in every copy).
const (
	// checkReloadSucceeded: no reload failed and kept serving, and the
	// last reload did not fail. Subject: "failed-and-serving" or
	// "last-reload-failed".
	checkReloadSucceeded = "reload-succeeded"
	// checkResumptionBound: session tickets are off, or verification is
	// re-run on a resumed session, so resumption cannot bypass the
	// access-control list. Subject: null.
	checkResumptionBound = "resumption-bound"
)

// materialSurfaceIdentifiers lists the surface's checks in evaluation
// order.
var materialSurfaceIdentifiers = []string{checkReloadSucceeded, checkResumptionBound}

// materialSurfaceFindings judges a readable current boot with a start
// line.
func materialSurfaceFindings(boot *gtBoot) []Finding {
	start := boot.Records[0].Start
	var out []Finding
	seen := map[Finding]bool{}
	fail := func(check string, subject string) {
		f := Finding{Check: check, Subject: subject}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	var lastReload *gtReload
	for i := range boot.Records {
		r := boot.Records[i].Reload
		if r == nil {
			continue
		}
		lastReload = r
		if r.Outcome == "failed" && r.Serving {
			fail(checkReloadSucceeded, "failed-and-serving")
		}
	}
	if lastReload != nil && lastReload.Outcome == "failed" {
		fail(checkReloadSucceeded, "last-reload-failed")
	}
	if start.Config.SessionTickets && !start.Config.VerifyOnResume {
		fail(checkResumptionBound, "")
	}
	return out
}
